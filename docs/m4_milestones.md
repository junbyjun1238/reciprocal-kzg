# ESP Grant M1-M4 Milestones

## 목표

이번 grant의 목표는 reciprocal backend를 **실제 KZG 기반 라이브러리**로 만들고,
그 경로를 Sonobe staging 위에 **실제로 연결되는 실험 백엔드**로 올리는 것이다.

핵심은 연구 메모를 더 쓰는 것이 아니라:

- KZG에 붙는 descriptor-opening 경로를 구현하고
- Sonobe 쪽 adapter / proof path에 연결하고
- aggregation / decider까지 이어서
- 리뷰어가 직접 돌려볼 수 있는 형태로 정리하는 것이다.

---

## M1. KZG Descriptor-Opening Library

### 작업

- reciprocal descriptor query를 처리하는 KZG 기반 commitment/opening 라이브러리 구현
- input commitment, descriptor query, output opening, verification 경로 구현
- 현재 Pedersen-backed PoC path를 라이브러리 레벨에서 대체할 수 있는 API 구성

### 산출물

- KZG-backed reciprocal commitment/opening 모듈
- descriptor query를 받는 open / verify API
- unit test와 worked-instance test

### 완료 기준

- reciprocal input을 KZG로 commit할 수 있다
- reduced descriptor query에 대해 opening proof를 생성할 수 있다
- verifier가 same output / wrong output / wrong descriptor를 구분해서 reject할 수 있다
- 현재 PoC example이 더 이상 Pedersen-only certificate path에만 의존하지 않는다

---

## M2. Sonobe Adapter Integration

### 작업

- KZG-backed reciprocal proof path를 Sonobe staging adapter에 연결
- 현재 reciprocal statement 경계를 실제 integration flow에서 소비되게 정리
- example / test 경로를 새 라이브러리 기준으로 교체

### 산출물

- reciprocal adapter의 KZG-backed path
- integration test 갱신
- example runner 갱신

### 완료 기준

- Sonobe staging 위에서 reciprocal statement가 새 라이브러리 경로로 생성된다
- integration test가 새 proof path를 직접 사용한다
- malformed output / wrong descriptor / wrong opening이 integration 경로에서 reject된다
- 리뷰어가 example 하나로 새 경로를 직접 실행해볼 수 있다

---

## M3. 4-Coordinate Aggregation and Decider

### 작업

- `F^4` output을 하나의 verification path로 묶는 aggregation 구현
- aggregated reciprocal proof를 소비하는 decider path 구성
- 현재 helper 성격의 offchain decider를 실제 library entry point 수준으로 끌어올림

### 산출물

- 4-coordinate aggregation 구현
- aggregated proof verification entry point
- decider path 테스트

### 완료 기준

- verifier가 좌표별 helper 조합이 아니라 aggregated reciprocal proof를 직접 받는다
- decider entry point 하나로 relation / opening / fold linkage를 체크할 수 있다
- example과 test가 aggregated path를 기준으로 동작한다

---

## M4. Hardening and Grant Demo Package

### 작업

- 새 KZG path 기준 benchmark 정리
- naive baseline 대비 specialized path 비교를 새 경로에 맞춰 다시 측정
- reviewer/demo용 실행 문서와 예제 정리

### 산출물

- 최신 benchmark snapshot
- reviewer용 실행 문서
- end-to-end demo 커맨드

### 완료 기준

- 한 번의 실행으로 reciprocal backend demo를 재현할 수 있다
- benchmark 표가 KZG-backed path 기준으로 갱신된다
- 리뷰어가 어떤 코드가 새 라이브러리이고 어떤 경로가 Sonobe integration인지 바로 따라갈 수 있다

---

## 메모

이 문서의 M1-M4는 구현 마일스톤이다.

- M1은 라이브러리를 만든다
- M2는 Sonobe에 붙인다
- M3는 aggregation / decider로 묶는다
- M4는 리뷰와 데모가 가능하게 다듬는다
