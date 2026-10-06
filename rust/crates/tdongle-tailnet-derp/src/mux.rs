//! The set of memberships one shared DERP task services (`ml_mux.c`, ADR 0013): a fixed number of slots, serviced in a rotating order so that no
//! slot is always last. There is no lock: the sans-IO links are plain values owned by the task that calls [`Mux::pass`].

/// Counters of a [`Mux`].
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct MuxStats {
    /// Members attached.
    pub attached: u32,
    /// Members detached.
    pub detached: u32,
    /// Attach attempts refused (full table).
    pub attach_refused: u32,
    /// Most members present at once.
    pub peak_members: u32,
    /// Passes made.
    pub passes: u32,
    /// Members serviced across all passes.
    pub serviced: u32,
}

/// A slot index handed out by [`Mux::attach`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Slot(pub usize);

/// Why an attach failed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Full;

/// `N` slots of `T`.
pub struct Mux<T, const N: usize> {
    slots: [Option<T>; N],
    start: usize,
    stats: MuxStats,
}

impl<T, const N: usize> core::fmt::Debug for Mux<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mux").field("members", &self.count()).field("stats", &self.stats).finish()
    }
}

impl<T, const N: usize> Default for Mux<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> Mux<T, N> {
    /// An empty mux.
    pub fn new() -> Self {
        Self { slots: core::array::from_fn(|_| None), start: 0, stats: MuxStats::default() }
    }

    /// Put a member in the first free slot. A full table returns the member back with [`Full`] (counted).
    pub fn attach(&mut self, member: T) -> Result<Slot, (Full, T)> {
        match self.slots.iter().position(|s| s.is_none()) {
            Some(i) => {
                self.slots[i] = Some(member);
                self.stats.attached += 1;
                self.stats.peak_members = self.stats.peak_members.max(self.count() as u32);
                Ok(Slot(i))
            }
            None => {
                self.stats.attach_refused += 1;
                Err((Full, member))
            }
        }
    }

    /// Remove a member and give it back. Nothing touches it afterwards.
    pub fn detach(&mut self, slot: Slot) -> Option<T> {
        let m = self.slots.get_mut(slot.0)?.take();
        if m.is_some() {
            self.stats.detached += 1;
        }
        m
    }

    /// The member in a slot.
    pub fn get_mut(&mut self, slot: Slot) -> Option<&mut T> {
        self.slots.get_mut(slot.0)?.as_mut()
    }

    /// Members present.
    pub fn count(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }

    /// Counters.
    pub fn stats(&self) -> MuxStats {
        self.stats
    }

    /// Service every member once, starting one slot later than the previous pass. Returns how many were serviced.
    pub fn pass(&mut self, mut service: impl FnMut(Slot, &mut T)) -> usize {
        let first = self.start;
        let mut n = 0;
        for k in 0..N {
            let i = (first + k) % N;
            if let Some(m) = self.slots[i].as_mut() {
                service(Slot(i), m);
                n += 1;
            }
        }
        self.start = (first + 1) % N.max(1);
        self.stats.passes += 1;
        self.stats.serviced += n as u32;
        n
    }

    /// Visit every member.
    pub fn for_each(&mut self, mut f: impl FnMut(Slot, &mut T)) {
        for (i, s) in self.slots.iter_mut().enumerate() {
            if let Some(m) = s {
                f(Slot(i), m);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_detach_and_refusal() {
        let mut m: Mux<u32, 2> = Mux::new();
        let a = m.attach(10).unwrap();
        let b = m.attach(20).unwrap();
        assert_eq!(m.attach(30).unwrap_err().1, 30);
        assert_eq!(m.stats().attach_refused, 1);
        assert_eq!(m.stats().peak_members, 2);
        assert_eq!(m.detach(a), Some(10));
        assert_eq!(m.detach(a), None);
        assert_eq!(m.count(), 1);
        assert_eq!(*m.get_mut(b).unwrap(), 20);
        assert!(m.attach(30).is_ok());
    }

    #[test]
    fn rotation_gives_every_slot_the_first_turn() {
        let mut m: Mux<u8, 3> = Mux::new();
        for v in 0..3 {
            m.attach(v).unwrap();
        }
        let mut firsts = std::vec::Vec::new();
        for _ in 0..3 {
            let mut order = std::vec::Vec::new();
            m.pass(|_, v| order.push(*v));
            assert_eq!(order.len(), 3);
            firsts.push(order[0]);
        }
        firsts.sort();
        assert_eq!(firsts, [0, 1, 2]);
        assert_eq!((m.stats().passes, m.stats().serviced), (3, 9));
    }
}
