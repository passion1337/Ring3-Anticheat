## Ring3(usermode) anticheat 

### Implemented features
- Client-Server communication via NamedPipe 
- Local process modification detection
- External process modification detection
- Debugger detection
- Vectored-Exception-Handler (VEH) detection
- Unlinked-module (from PEB) detection
- Debug register detection
- Dynamic-code (RWX page) detection
- Manual-mapping detection
- Standard DLL-injection detection
- Window detection (by EnumWindows + EnumChildWindows)
- Process detection (by name & signature)
- Driver detection (by name & signature)
- handle detection to find Cheat Engine, handle hijack
- ObRegisterCallback detection
- Scanning the Prefetch folder to check file history
- Scanning the Registry to check file history
- Monitoring "Debug String" to identify strings used by malicious programs (e.g., Cheat Engine, well-known drivers like Blackbone, etc.)

### todo 
- when unsigned-module is loaded, dump & send it to server for analysis. 
- send loaded-dll certification info and analyze
- dynamically downloading shellcode or yara rules from server

### result video 
[![Video Label](http://img.youtube.com/vi/71WO0KogFrY/0.jpg)](https://youtu.be/71WO0KogFrY)

### my opinion
실제로 Cheating을 완전히 차단하기란 불가능하다고 생각한다. 그보다 이를 어떻게 탐지할 것인가에 초점을 두어야 함. "여러 Detection vector를 만들고 가중치를 부여, 이 가중치 합이 임계점을 초과한다면 비정상 유저로 판단하는 방식"은 장기적으로 적절한 가중치가 도출됨으로서 오탐을 최소화 할 수 있는 좋은 전략이라고 생각 함. 

