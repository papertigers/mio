#![allow(deprecated)]
use std::collections::HashMap;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering, ATOMIC_USIZE_INIT};
use std::sync::Mutex;
use std::time::Duration;
use std::{cmp, ptr};

use libc::{self, c_int, time_t};
use libc::{POLLIN, POLLOUT};

use event_imp::{self as event, Event};
use sys::unix::io::set_cloexec;
use sys::unix::{cvt, UnixReady};
use {io, PollOpt, Ready, Token};

/// Each Selector has a globally unique(ish) ID associated with it. This ID
/// gets tracked by `TcpStream`, `TcpListener`, etc... when they are first
/// registered with the `Selector`. If a type that is previously associated with
/// a `Selector` attempts to register itself with a different `Selector`, the
/// operation will return with an error. This matches windows behavior.
static NEXT_ID: AtomicUsize = ATOMIC_USIZE_INIT;

/// event port "user" field in `port_associate`
type PortEvUser = *mut ::libc::c_void;
/// event port "object" field in `port_associate` aka the fd
type PortEvObject = ::libc::uintptr_t;
/// event port "nget" and "max" fields in `port_getn`
type Count = ::libc::c_uint;

/// Generates a `port_associate` call with all the proper casting.
macro_rules! port_associate {
    ($port:expr, $object:expr, $events:expr, $user:expr) => {
        libc::port_associate(
            $port,
            libc::PORT_SOURCE_FD, // always operating in this mode
            $object as PortEvObject,
            $events as c_int,
            $user as PortEvUser,
        )
    };
}

#[derive(Debug)]
struct TokenInfo {
    token: Token,
    flags: c_int,
    edge_triggered: bool,
    needs_rearm: bool,
}

#[derive(Debug)]
pub struct Selector {
    id: usize,
    port: RawFd,
    /// Keeps track of whether or not `fd_to_reassociate` contains any elements to help avoid
    /// grabbing a mutex if possible.
    has_fd_to_reassociate: AtomicBool,
    /// Keeps a list of RawFds that need to be reassociated with `port_associate` after a call to
    /// `port_getn`, since event ports are always oneshot and intended to be used in a
    /// multithreaded environment.
    fd_to_reassociate: Mutex<HashMap<RawFd, TokenInfo>>,
}

impl Selector {
    pub fn new() -> io::Result<Selector> {
        // offset by 1 to avoid choosing 0 as the id of a selector
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed) + 1;
        let port = unsafe { cvt(libc::port_create())? };
        let has_fd_to_reassociate = AtomicBool::new(false);
        let fd_to_reassociate = Mutex::new(HashMap::new());
        drop(set_cloexec(port));

        Ok(Selector {
            id,
            port,
            has_fd_to_reassociate,
            fd_to_reassociate,
        })
    }

    pub fn id(&self) -> usize {
        self.id
    }

    /// Wait for events from the OS
    pub fn select(
        &self,
        evts: &mut Events,
        awakener: Token,
        timeout: Option<Duration>,
    ) -> io::Result<bool> {
        let timeout = timeout.map(|to| libc::timespec {
            tv_sec: cmp::min(to.as_secs(), time_t::max_value() as u64) as time_t,
            tv_nsec: to.subsec_nanos() as libc::c_long,
        });

        let timeout = timeout
            .as_ref()
            .map(|s| s as *const _)
            .unwrap_or(ptr::null_mut());

        // Handle level-triggered reassociate if needed
        if self.has_fd_to_reassociate.load(Ordering::Acquire) {
            let fd_to_reassociate_lock = self.fd_to_reassociate.lock().unwrap();
            for (fd, ti) in fd_to_reassociate_lock.iter() {
                if ti.needs_rearm  && !ti.edge_triggered {
                    // XXX handle possible error
                    unsafe { port_associate!(self.port, *fd, ti.flags, usize::from(ti.token)) };
                }
            }
        }

        evts.clear();
        unsafe {
            let mut nget: u32 = 1;
            let ret = libc::port_getn(
                self.port,
                evts.sys_events.0.as_mut_ptr(),
                evts.sys_events.0.capacity() as Count,
                &mut nget as *mut ::libc::c_uint,
                timeout as *mut ::libc::timespec,
            );

            // Handle edge-triggered reassociate if needed
            if self.has_fd_to_reassociate.load(Ordering::Acquire) {
                let fd_to_reassociate_lock = self.fd_to_reassociate.lock().unwrap();
                for (fd, ti) in fd_to_reassociate_lock.iter() {
                    if ti.needs_rearm  && ti.edge_triggered {
                        // XXX handle possible error
                        port_associate!(self.port, *fd, ti.flags, usize::from(ti.token));
                    }
                }
            }

            match ret {
                -1 => {
                    let os_error = io::Error::last_os_error();
                    match os_error.raw_os_error().unwrap() {
                        // ETIME is valid return value for event ports, so we have to check for
                        // events that need to be processed
                        libc::ETIME | libc::EAGAIN | libc::EINTR  => {
                            evts.sys_events.0.set_len(nget as usize);
                            Ok(evts.coalesce(awakener, &self))
                        }
                        _ => Err(os_error),
                    }
                }
                _ => {
                    // port_getn should only ever return 0 or -1
                    debug_assert_eq!(ret, 0);

                    evts.sys_events.0.set_len(nget as usize);
                    Ok(evts.coalesce(awakener, &self))
                }
            }
        }
    }

    /// Register event interests for the given IO handle with the OS
    pub fn register(
        &self,
        fd: RawFd,
        token: Token,
        interests: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        let mut flags = 0;
        let edge_triggered = opts.is_edge();

        if interests.is_readable() {
            flags |= POLLIN;
        }

        if interests.is_writable() {
            flags |= POLLOUT;
        }

        if !opts.is_oneshot() {
            let mut fd_to_reassociate_lock = self.fd_to_reassociate.lock().unwrap();
            fd_to_reassociate_lock.entry(fd).or_insert(
                TokenInfo {
                    token,
                    flags: flags as i32,
                    edge_triggered,
                    needs_rearm: false,
                }
            );
            self.has_fd_to_reassociate.store(true, Ordering::Release);
        }

        unsafe {
            cvt(port_associate!(self.port, fd, flags, usize::from(token)))?;
        }

        Ok(())
    }

    /// Register event interests for the given IO handle with the OS
    pub fn reregister(
        &self,
        fd: RawFd,
        token: Token,
        interests: Ready,
        opts: PollOpt,
    ) -> io::Result<()> {
        self.register(fd, token, interests, opts)
    }

    /// Deregister event interests for the given IO handle with the OS
    pub fn deregister(&self, fd: RawFd) -> io::Result<()> {
        let mut cleanup: bool = true;

        // We need to check for any fd's that might be set to rearm but haven't yet
        if self.has_fd_to_reassociate.load(Ordering::Acquire) {
            let mut fd_to_reassociate_lock = self.fd_to_reassociate.lock().unwrap();
            match fd_to_reassociate_lock.get(&fd) {
                Some(info) => {
                    if info.needs_rearm {
                        cleanup = false
                    }
                }
                None => cleanup = true,
            }

            let _ = fd_to_reassociate_lock.remove(&fd);
            let has_fds = fd_to_reassociate_lock.len() > 0;
            self.has_fd_to_reassociate.store(has_fds, Ordering::Release);
        }

        if cleanup {
            unsafe {
                cvt(libc::port_dissociate(
                    self.port,
                    libc::PORT_SOURCE_FD,
                    fd as ::libc::uintptr_t,
                ))?;
            }
        }
        Ok(())
    }
}

impl AsRawFd for Selector {
    fn as_raw_fd(&self) -> RawFd {
        self.port
    }
}

impl Drop for Selector {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::close(self.port);
        }
    }
}

pub struct Events {
    sys_events: PortEventList,
    events: Vec<Event>,
    event_map: HashMap<Token, usize>,
}

struct PortEventList(Vec<libc::port_event>);

unsafe impl Send for PortEventList {}
unsafe impl Sync for PortEventList {}

impl Events {
    pub fn with_capacity(cap: usize) -> Events {
        Events {
            sys_events: PortEventList(Vec::with_capacity(cap)),
            events: Vec::with_capacity(cap),
            event_map: HashMap::with_capacity(cap),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.events.capacity()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn get(&self, idx: usize) -> Option<Event> {
        self.events.get(idx).map(|e| *e)
    }

    fn coalesce(&mut self, awakener: Token, selector: &Selector) -> bool {
        let mut ret = false;
        self.events.clear();
        self.event_map.clear();

        for e in self.sys_events.0.iter() {
            let token = Token(e.portev_user as usize);
            let fd: RawFd = e.portev_object as RawFd;
            let len = self.events.len();

            if token == awakener {
                ret = true;
                continue;
            }

            let idx = *self.event_map.entry(token).or_insert(len);

            if idx == len {
                // New entry, insert the default
                self.events.push(Event::new(Ready::empty(), token));
            }

            if e.portev_events as i16 & libc::POLLERR != 0 {
                event::kind_mut(&mut self.events[idx]).insert(*UnixReady::error());
            }

            if e.portev_events as i16 & libc::POLLIN != 0 {
                event::kind_mut(&mut self.events[idx]).insert(Ready::readable());
            }

            if e.portev_events as i16 & libc::POLLOUT != 0 {
                event::kind_mut(&mut self.events[idx]).insert(Ready::writable());
            }

            if e.portev_events as i16 & libc::POLLHUP != 0 {
                event::kind_mut(&mut self.events[idx]).insert(UnixReady::hup());
            }

            // Handle reassociate if needed
            if selector.has_fd_to_reassociate.load(Ordering::Acquire) {
                let mut fd_to_reassociate_lock = selector.fd_to_reassociate.lock().unwrap();
                if let Some(ti) = fd_to_reassociate_lock.get_mut(&fd) {
                    ti.needs_rearm = true;
                }
            }
        }

        ret
    }

    pub fn push_event(&mut self, event: Event) {
        self.events.push(event);
    }

    pub fn clear(&mut self) {
        self.sys_events.0.truncate(0);
        self.events.truncate(0);
        self.event_map.clear();
    }
}
