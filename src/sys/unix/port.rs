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
type Count = ::libc::uint32_t;

/// Generates a `port_associate` call with all the proper casting.
macro_rules! port_associate {
    ($port:expr, $object:expr, $events:expr, $user:expr) => {
        libc::port_associate(
            $port,
            libc::PORT_SOURCE_FD, // always operating in this mode
            $object as PortEvObject,
            $events as c_int,
            usize::from($user) as PortEvUser,
        )
    };
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
    fd_to_reassociate: Mutex<Vec<RawFd>>,
}

impl Selector {
    pub fn new() -> io::Result<Selector> {
        // offset by 1 to avoid choosing 0 as the id of a selector
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed) + 1;
        let port = unsafe { cvt(libc::port_create())? };
        let has_fd_to_reassociate = AtomicBool::new(false);
        let fd_to_reassociate = Mutex::new(Vec::new());
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

        evts.clear();
        unsafe {
            let nget: u32 = 1;
            let ret = libc::port_getn(
                self.port,
                evts.sys_events.0.as_mut_ptr(),
                evts.sys_events.0.capacity() as Count,
                nget as *mut Count,
                timeout as *mut ::libc::timespec,
            );

            match ret {
                -1 => {
                    // TODO handle ETIME... MANTA-3112
                    let os_error = Err(io::Error::last_os_error());
                    os_error
                }
                _ => {
                    // port_getn should only ever return 0 or -1
                    debug_assert_eq!(ret, 0);

                    let nget = nget as usize;
                    evts.sys_events.0.set_len(nget);
                    Ok(evts.coalesce(awakener))
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

        if interests.is_readable() {
            flags |= POLLIN;
        }

        if interests.is_writable() {
            flags |= POLLOUT;
        }

        if !opts.is_oneshot() {
            let mut fd_to_reassociate_lock = self.fd_to_reassociate.lock().unwrap();
            if !fd_to_reassociate_lock.contains(&fd) {
                fd_to_reassociate_lock.push(fd);
                self.has_fd_to_reassociate.store(true, Ordering::Release);
            }
        }

        // TODO figure out what to do about edge triggered since event ports doesn't support it

        unsafe {
            cvt(port_associate!(self.port, fd, flags, token))?;
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
        unsafe {
            cvt(libc::port_dissociate(
                self.port,
                libc::PORT_SOURCE_FD,
                fd as ::libc::uintptr_t,
            ))?;
        }

        // If we know there are fds that are not registered with oneshot we need to safely remove
        // the de-registering fd from fd_to_reassociate if we were tracking it
        if self.has_fd_to_reassociate.load(Ordering::Acquire) {
            let mut fd_to_reassociate_lock = self.fd_to_reassociate.lock().unwrap();

            // Evaluate how expensive this is when watching a lot of fds
            // There is no order to the Vec so we use swap_remove to be more efficient
            fd_to_reassociate_lock
                .iter()
                .position(|&i| i == fd)
                .map(|idx| fd_to_reassociate_lock.swap_remove(idx));

            let has_fds = fd_to_reassociate_lock.len() > 0;
            self.has_fd_to_reassociate.store(has_fds, Ordering::Release);
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

    fn coalesce(&mut self, awakener: Token) -> bool {
        let mut ret = false;
        self.events.clear();
        self.event_map.clear();

        for e in self.sys_events.0.iter() {
            let token = Token(e.portev_user as usize);
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
        }

        ret
    }

    pub fn push_event(&mut self, event: Event) {
        self.events.push(event);
    }

    pub fn clear(&mut self) {
        self.events.truncate(0);
    }
}
