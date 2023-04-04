# ecb
## ECB (Extended Centralized Bus) protocol description
### App Codes

| Code  | Name                          |
|-------|-------------------------------|
| 0     | OK                            |
| -1    | ERROR NO_SIGNAL               |
| -4    | ERROR INTERNAL                |
| -5    | ERROR INCORRECT DATA          |
| -16   | ERROR BOOT INCORRECT_CHECKSUM |
| -17   | ERROR BOOT INCORRECT_KEY      |

### Default signals

| Code  | Name                          | Description |
|-------|-------------------------------|-------------|
| 0     | RESET                         | Any write perform reset device |
| 1     | INFO                          | Read will be return information aboud currently executing program |
| 2     | BOARD_NAME                    | Read board name |
| 15    | PICK                          | For notify or check established connection |
| 16    | BOOT BEGIN                    | Initialize firmware upload (bootloaders only) |
| 17    | BOOT END                      | Terminate firmare upload (bootloaders only) |
| 18    | BOOT CHECKSUM                 | Read will be return CRC32 checksum of uploaded firmware (bootloaders only) |
| 20    | BOOT WRITE                    | Write the next firmware block |
| 22    | BOOT APP_INFO                 | Read will be return last uploaded firmware info (bootloaders only) |
| 23    | BOOT GO_APP                   | Any write leads to a transition to the app firmware (bootloaders only) |
| 24    | AUTH_KEY                      | Setup new auth key |
| 25    | RANDOM_NUMBER                 |  |
