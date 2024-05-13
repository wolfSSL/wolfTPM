# wolfTPM for Espressif

Initial minimum memory requirements: 35KB Stack. See `sdkconfig.defaults`.

Current memory assigned: 50960

## Pin assignments

**Note:** The following pin assignments are used by default, you can change these in the `menuconfig` .

|                  | SDA            | SCL            |
| ---------------- | -------------- | -------------- |
| ESP I2C Master   | I2C_MASTER_SDA | I2C_MASTER_SCL |
| TPM2 Device      | SDA            | SCL            |

For the actual default value of `I2C_MASTER_SDA` and `I2C_MASTER_SCL` see `Example Configuration` in `menuconfig`.

**Note:** There's no need to add an external pull-up resistors for SDA/SCL pin, because the driver will enable the internal pull-up resistors.

## Troubleshooting

If problems are encountered with the I2C module:

- Beware that printing to the UART during an I2C transaction may affect timing and cause errors.
- Ensure the TPM module has been reset after flash updated.
- Check wiring. `SCL` to `SCL`, `SDA` to `SDA`. Probably best to ensure GND is connected. Vcc is 3.3v only.
- Ensure the proper pins are connected on the ESP32. SCL default is `GPIO 19`;  SDA default is `GPIO 18`.
- Test with only a single I2C device before testing concurrent with other I2C boards.
- When using multiple I2C boards, check for appropriate pullups. See data sheet.
- Reset TPM device again. Press button on TPM SLB9673 eval board or set TPM pin 17 as appropriate.
- 