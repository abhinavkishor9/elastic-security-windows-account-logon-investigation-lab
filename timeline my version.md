# Timeline 

| Time | Activity | Event / Artifact | Evidence / Notes |
|---|---|---|---|
| Initial phase | Account inventory | Local users | Multiple enabled and disabled local accounts identified |
| Initial phase | Current-user validation | `whoami` | Current account confirmed as `desktop-9mmm37v\dell` |
| Initial phase | Security log query | 4624 / 4625 | Initial query returned no events |
| 06:15:30 | Successful authentication | 4624 | `SYSTEM` / `DESKTOP-9MMM37V$` activity observed |
| 06:15:34–06:15:47 | Repeated successful authentication | 4624 | Multiple local authentication events |
| 06:16:00.783 | Successful authentication | 4624 | `SYSTEM` and machine-account activity |
| 06:16:43.075 | Successful authentication | 4624 | `DESKTOP-9MMM37V$` / `SYSTEM` activity |
| 06:18:25.396 | Successful authentication | 4624 | `SYSTEM` and machine-account activity |
| 06:18:36.429 | Successful authentication | 4624 | `SYSTEM` / machine-account activity |
| Controlled activity | Workstation lock | `rundll32.exe user32.dll,LockWorkStation` | Benign lock/unlock activity |
| 06:24:55.739 | Interactive logon | 4624 | `Dell`, Logon Type `2` |
| 06:24:56.021 | Service logon | 4624 | `SYSTEM`, Logon Type `5` |
| Investigation | Failed-logon hunt | 4625 | No matching documents |
| Investigation | Special-privilege hunt | 4672 | No matching documents |
| Investigation | Remote Interactive hunt | Logon Type `10` | No matching documents |

