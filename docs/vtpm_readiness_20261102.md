# Workstation Pro vTPM 사전 확인

2026-11-02, 읽기전용 조사. 사용자 제품 선택은 Workstation Pro, 정확 버전은 아직 제공되지 않음.

- 게스트: VMware Virtual Platform, hypervisor vmware.
- /dev/tpm0 및 /dev/tpmrm0 없음, /sys/class/tpm 항목0.
- tpm2_getcap 미설치.
- /sys/firmware/efi 없음. BIOS 부팅이거나 조사 환경에서 EFI가 노출되지 않은 상태다. 펌웨어를 변경해도 안전하다고 판단할 근거가 없다.
- 키 이관/운영 강제모드/VM전원/재부팅/펌웨어/키 생성 등 변경 없음.

Workstation Pro의 정식 경로는 VM암호화와 가상 Trusted Platform Module 장치 추가다. 버전별 옵션이 달라 먼저 호스트 Help > About VMware Workstation의 버전을 확인해야 한다. Windows11 설치 우회나 vmx 비지원 옵션은 API키 보호 수단으로 사용하지 않는다.

작업 전 운영 중단 범위를 승인받고 복구 가능한 VM전체 백업과 현재 부팅 설정을 기록한다. VM암호화 비밀번호·복구정보는 VM파일/일반 백업과 분리 보호한다. 키/비밀번호를 채팅에 올리지 않는다. 현재 Ubuntu의 BIOS/UEFI 전환은 별도 호환성·복구 검증 없이는 수행하지 않는다.

vTPM 노출 뒤 게스트의 TPM기능/권한을 확인하고, 애플리케이션용 키 sealing/unsealing 및 VM복원/TPM소실 복구 검증을 별도로 구현한다. 현재 secret_store의 실백엔드는 AWS KMS다. TPM디바이스를 추가하는 것만으로 AES암호화 키보호나 운영 API키 이관이 완료되지 않는다. VM호스트 관리자와 함께 복사된 VM/vTPM에 대한 위협모델도 검토한다.

근거: https://knowledge.broadcom.com/external/article/315650

추가 확인: 사용자 버전표기17.64를17.6.4로 해석했다. /boot/efi가 마운트되어 있고 BIOS/EFI GRUB 모듈이 모두 존재한다. sysfs EFI 미노출만으로 BIOS라고 확정할 수 없다. VMware호스트 UI의 현재 Firmware type을 확인해야 하며 기존 모드는 변경하지 않는다. VM암호화 및 TPM추가 메뉴는 호스트에서만 설정할 수 있다. 근거: https://knowledge.broadcom.com/external/article/388094
