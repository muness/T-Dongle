# Display readback review

Fresh manual diff review (sg unavailable) checked that the new command is read-only, capability-advertised, bounded and uses the same rolled-back configuration as the existing display handler. Host settings tests and pinned ESP-IDF full build/USB descriptor checks pass. Existing public/physical controls remain unchanged. Brightness, both rotations, dim timing and wake require physical acceptance; none was performed.
