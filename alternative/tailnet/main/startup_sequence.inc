static void gateway_startup_sequence(void) {
    bool usb=start_usb()==0;
    gateway_boot_begin();
    gateway_boot_result(BOOT_USB,usb?0:ESP_FAIL);
    bool settings=start_step(BOOT_SETTINGS,start_settings);
    /* A crash loop outranks a setup request: recovery starts no new radio stack. */
    if(gateway_boot_recovery())setup_active=false;
    bool network=start_step(BOOT_NETWORK,start_network);
    if(network && (gateway_tailnet_mode() || setup_active))start_step(BOOT_HTTP,start_http);
    start_step(BOOT_DISPLAY,start_display);
    /* A crash quarantines automatic tailnet activation, not USB management.
     * Wi-Fi settings and saved identities remain untouched. */
    if(!gateway_boot_recovery()) {
        if(setup_active) {
            /* The setup access point (ADR 0023) and nothing else: no bridge, no tailnet runtime, no manager. */
            if(settings && network)start_step(BOOT_SETUP,start_setup);
        } else {
            bool directory=gateway_tailnet_mode() && settings && start_step(BOOT_DIRECTORY,start_directory);
            if(directory)start_step(BOOT_ROUTES,start_routes);
            bool wifi=settings && network && start_step(BOOT_WIFI,start_wifi);
            if(network && wifi && gateway_tailnet_mode())start_step(BOOT_DNS,start_dns);
            if(wifi)start_step(BOOT_MANAGER,start_manager);
        }
    }
    gateway_boot_complete();
}
