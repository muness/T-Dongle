//! The USB PHY, the TinyUSB task, and the mount/unmount callbacks.
//!
//! Port of `components/esp_tinyusb/{tinyusb.c, tinyusb_task.c}` for one full-speed device port.

use core::sync::atomic::{AtomicU32, Ordering};

use esp_idf_svc::hal::cpu::Core;
use esp_idf_svc::hal::task::thread::ThreadSpawnConfiguration;
use esp_idf_svc::sys::{self, EspError};

use super::prio;
use crate::sys::task::{Notified, ms_to_ticks, notify_take};

/// Stack of the TinyUSB task (`TINYUSB_DEFAULT_TASK_SIZE`). The network and console callbacks run on it; the high-water mark is reported by
/// `status` (`control_stack_free_bytes` is the control task's; this one is in the `usb` health line of the diagnostics).
const STACK_BYTES: usize = 4096;

static STARTED: Notified = Notified::new();

/// Bus resets and unplugs, for the Health screen (v0.1.1 showed "USB resets"): `tud_event_hook_cb` counts them.
static BUS_RESETS: AtomicU32 = AtomicU32::new(0);
static SUSPENDS: AtomicU32 = AtomicU32::new(0);
static RESUMES: AtomicU32 = AtomicU32::new(0);

/// Install the PHY and start the TinyUSB task on core 1; wait for the stack to be up (the C waits 5 s).
///
/// # Errors
/// The PHY could not be created, the task could not be spawned, or the stack did not start in 5 seconds.
pub fn start() -> Result<(), EspError> {
    let phy = sys::usb_phy_config_t {
        controller: sys::usb_phy_controller_t_USB_PHY_CTRL_OTG,
        target: sys::usb_phy_target_t_USB_PHY_TARGET_INT,
        otg_mode: sys::usb_otg_mode_t_USB_OTG_MODE_DEVICE,
        otg_speed: sys::usb_phy_speed_t_USB_PHY_SPEED_FULL,
        ext_io_conf: core::ptr::null(),
        otg_io_conf: core::ptr::null(),
    };
    let mut handle: sys::usb_phy_handle_t = core::ptr::null_mut();
    // SAFETY: `phy` and `handle` are valid for the call; the PHY lives for the life of the firmware.
    sys::esp!(unsafe { sys::usb_new_phy(&phy, &mut handle) })?;

    STARTED.register_current_task();
    ThreadSpawnConfiguration {
        name: Some(c"TinyUSB"),
        stack_size: STACK_BYTES,
        priority: prio::TINYUSB as u8,
        pin_to_core: Some(Core::Core1),
        ..Default::default()
    }
    .set()
    .map_err(|_| EspError::from_infallible::<{ sys::ESP_ERR_NO_MEM }>())?;
    let spawned = std::thread::Builder::new().name("TinyUSB".into()).stack_size(STACK_BYTES).spawn(device_task);
    ThreadSpawnConfiguration::default().set().ok();
    spawned.map_err(|_| EspError::from_infallible::<{ sys::ESP_ERR_NO_MEM }>())?;
    if notify_take(ms_to_ticks(5000)) == 0 {
        return Err(EspError::from_infallible::<{ sys::ESP_ERR_TIMEOUT }>());
    }
    Ok(())
}

/// `tinyusb_device_task`: initialise the stack on the device port, tell the parent, and serve USB events for ever.
fn device_task() {
    let init = sys::tusb_rhport_init_t { role: sys::tusb_role_t_TUSB_ROLE_DEVICE, speed: sys::tusb_speed_t_TUSB_SPEED_FULL };
    // SAFETY: `init` is valid for the call; port 0 is the S3's only OTG controller.
    let up = unsafe { sys::tusb_rhport_init(0, &init) };
    if !up {
        log::error!("TinyUSB: stack initialisation failed");
        return;
    }
    STARTED.give();
    loop {
        // SAFETY: the TinyUSB device task loop, `tud_task()` of tusb.h: wait forever for an event, do not stop on an empty queue.
        unsafe { sys::tud_task_ext(u32::MAX, false) };
    }
}

/// `tud_mount_cb`: the host selected the configuration.
#[unsafe(no_mangle)]
pub extern "C" fn tud_mount_cb() {}

/// `tud_umount_cb`: the host unselected the configuration, or the cable left. Frames queued for the host that left are stale: flush them and
/// release the clock hold (`usb_event` in gateway_main.c).
#[unsafe(no_mangle)]
pub extern "C" fn tud_umount_cb() {
    super::ring::link_down();
}

/// `tud_suspend_cb`: fixed counters only, no I/O, allocation or USB reset.
#[unsafe(no_mangle)]
pub extern "C" fn tud_suspend_cb(_remote_wakeup_enabled: bool) {
    SUSPENDS.fetch_add(1, Ordering::Relaxed);
}

/// `tud_resume_cb`.
#[unsafe(no_mangle)]
pub extern "C" fn tud_resume_cb() {
    RESUMES.fetch_add(1, Ordering::Relaxed);
}

/// `tud_event_hook_cb`: bus resets and unplugs. TinyUSB calls it from its device task and, for some events, from the interrupt: a relaxed
/// counter is all it may do.
#[unsafe(no_mangle)]
pub extern "C" fn tud_event_hook_cb(_rhport: u8, event_id: u32, _in_isr: bool) {
    if event_id == sys::dcd_eventid_t_DCD_EVENT_BUS_RESET || event_id == sys::dcd_eventid_t_DCD_EVENT_UNPLUGGED {
        BUS_RESETS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Bus resets and unplugs since boot (`gateway_usb_health(8)`: `usb_resets=` in the `traffic` status line).
pub fn bus_resets() -> u32 {
    BUS_RESETS.load(Ordering::Relaxed)
}

/// `tud_mounted()`: the host has configured the device (`usb_enumerated=`).
pub fn mounted() -> bool {
    // SAFETY: reads TinyUSB's device state.
    unsafe { sys::tud_mounted() }
}

/// `tud_ready()`: mounted and not suspended (`usb_transport_ready=`). `static inline` in tusb.h, so it is spelled out here.
pub fn ready() -> bool {
    // SAFETY: reads TinyUSB's device state.
    mounted() && !unsafe { sys::tud_suspended() }
}
