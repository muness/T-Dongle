static void gateway_startup_sequence(void) {
    bool usb=start_usb()==0;
    gateway_boot_begin();
    gateway_boot_result(BOOT_USB,usb?0:ESP_FAIL);
    bool settings=start_step(BOOT_SETTINGS,start_settings);
    bool network=start_step(BOOT_NETWORK,start_network);
    if(network)start_step(BOOT_HTTP,start_http);
    start_step(BOOT_DISPLAY,start_display);
    /* A crash quarantines automatic tailnet activation, not USB management.
     * Wi-Fi settings and saved identities remain untouched. */
    if(!gateway_boot_recovery()) {
        bool directory=settings && start_step(BOOT_DIRECTORY,start_directory);
        bool routes=directory && start_step(BOOT_ROUTES,start_routes);
        bool wifi=settings && network && start_step(BOOT_WIFI,start_wifi);
        if(network && wifi)start_step(BOOT_DNS,start_dns);
        if(routes && wifi)start_step(BOOT_MANAGER,start_manager);
    }
    gateway_boot_complete();
}
