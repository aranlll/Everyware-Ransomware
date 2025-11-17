#include "ShadowCopy.h"

HRESULT DeleteShadowCopy()
{
    // VSS COM 인터페이스를 위한 스마트 포인터
    CComPtr<IVssBackupComponents>   m_pVssObject;
    CComPtr<IVssEnumObject>         pIEnumSnapshots;

    VSS_OBJECT_PROP                 Prop{};
    VSS_SNAPSHOT_PROP& Snap = Prop.Obj.Snap;
    HRESULT                         hr = S_OK;
    bool                            co_inited = false;

    // === 1. COM 라이브러리 초기화 ===
    // (COINIT_MULTITHREADED 권장; 이미 다른 모드로 초기화되어 있으면 RPC_E_CHANGED_MODE 허용)
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) {
        co_inited = true;
    }
    else if (hr == RPC_E_CHANGED_MODE) {
        // 이미 다른 모드로 초기화된 경우 - 계속 진행(보통 동작에 문제 없음)
    }
    else {
        printf("[!] CoInitializeEx Failed : 0x%0.8X \n", hr);
        return hr;
    }

    // === 2. COM 보안 초기화 ===
    // VSS는 높은 수준의 인증 및 가장 레벨이 필요할 수 있음
    hr = CoInitializeSecurity(
        NULL, -1, NULL, NULL,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL, EOAC_DYNAMIC_CLOAKING, NULL
    );
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) {
        printf("[!] CoInitializeSecurity Failed : 0x%0.8X \n", hr);
        if (co_inited) CoUninitialize();
        return hr;
    }

    // === 3. VSS 백업 구성 요소 생성 ===
    hr = CreateVssBackupComponents(&m_pVssObject);
    if (hr == E_ACCESSDENIED) { // 관리자 권한 확인
        printf("[!] Please Run As Admin To Delete Shadow Copies \n");
        if (co_inited) CoUninitialize();
        return hr;
    }
    if (FAILED(hr) || !m_pVssObject) {
        printf("[!] CreateVssBackupComponents Failed : 0x%0.8X \n", hr);
        if (co_inited) CoUninitialize();
        return hr;
    }

    // === 4. VSS 백업 작업 초기화 ===
    hr = m_pVssObject->InitializeForBackup();
    if (FAILED(hr)) {
        printf("[!] InitializeForBackup Failed : 0x%0.8X \n", hr);
        if (co_inited) CoUninitialize();
        return hr;
    }

    // 컨텍스트 설정 (모든 컨텍스트)
    hr = m_pVssObject->SetContext(VSS_CTX_ALL);
    if (FAILED(hr)) {
        printf("[!] SetContext Failed : 0x%0.8X \n", hr);
        if (co_inited) CoUninitialize();
        return hr;
    }

    // 백업 상태 설정
    hr = m_pVssObject->SetBackupState(TRUE, TRUE, VSS_BT_FULL, FALSE);
    if (FAILED(hr)) {
        printf("[!] SetBackupState Failed : 0x%0.8X \n", hr);
        if (co_inited) CoUninitialize();
        return hr;
    }

    // === 5. 섀도 복사본 쿼리 ===
    hr = m_pVssObject->Query(GUID_NULL, VSS_OBJECT_NONE, VSS_OBJECT_SNAPSHOT, &pIEnumSnapshots);
    if (hr == VSS_E_OBJECT_NOT_FOUND || !pIEnumSnapshots) { // 섀도 복사본이 없는 경우
        printf("[i] There Is No Shadow Copies On This Machine \n");
        if (co_inited) CoUninitialize();
        return S_FALSE; // 결과 없음 (실패 아님)
    }
    if (FAILED(hr)) {
        printf("[!] Query Failed : 0x%0.8X \n", hr);
        if (co_inited) CoUninitialize();
        return hr;
    }

    // === 6. 모든 섀도 복사본 순회 및 삭제 ===
    HRESULT hr_last = S_OK;

    while (TRUE) {
        ULONG ulFetched = 0;
        // 다음 섀도 복사본 가져오기
        hr = pIEnumSnapshots->Next(1, &Prop, &ulFetched);

        if (FAILED(hr)) {
            printf("[!] IVssEnumObject::Next Failed : 0x%0.8X \n", hr);
            hr_last = hr;
            break;
        }

        if (ulFetched == 0) {
            printf("[+] No More Shadow Copies Were Detected \n");
            break; // 루프 종료
        }

        if (Prop.Type != VSS_OBJECT_SNAPSHOT) {
            continue; // 비정상 타입은 건너뜀
        }

        LONG   lSnapshots = 0;
        VSS_ID idNonDeletedSnapshotID = GUID_NULL;

        // 삭제할 섀도 복사본 정보 출력
        wprintf(L"[i] Deleting shadow copy: " WSTR_GUID_FMT L" on %s from the provider: " WSTR_GUID_FMT L"\n",
            GUID_PRINTF_ARG(Snap.m_SnapshotId),
            (Snap.m_pwszOriginalVolumeName ? Snap.m_pwszOriginalVolumeName : L"(null)"),
            GUID_PRINTF_ARG(Snap.m_ProviderId));

        // 섀도 복사본 삭제 실행
        hr = m_pVssObject->DeleteSnapshots(
            Snap.m_SnapshotId,
            VSS_OBJECT_SNAPSHOT,
            FALSE,
            &lSnapshots,
            &idNonDeletedSnapshotID
        );

        if (FAILED(hr)) {
            printf("[!] DeleteSnapshots Failed: 0x%0.8X \n", hr);
            hr_last = hr; // 실패를 기록하되 계속 진행
        }

        // === 수정된 VSS 속성 구조체 메모리 해제 ===
        ::VssFreeSnapshotProperties(&Snap);
    }

    // === 7. COM 라이브러리 정리 ===
    if (co_inited) CoUninitialize();
    return hr_last;
}