# ESP Grant Reciprocal PoC Checklist

## 목적

이 문서는 현재 `sonobe_staging` 코드베이스에서 **추가로 구현해야 할 것**을
ESP grant용 PoC 기준으로 정리한 체크리스트다.

중요한 원칙은 두 가지다.

- 이번 목표는 **full scheme 완성**이 아니다.
- 그렇다고 **장난감 shape-test** 수준에 머물러도 안 된다.

즉, 이 체크리스트의 목적은 아래 한 문장으로 요약된다.

> "심사자가 이 PoC를 보고, 이미 핵심 백엔드는 진짜로 움직이고 있으며, 추가 자금으로 descriptor-consuming opening layer와 decider를 완성할 가치가 있다고 느끼게 만든다."

---

## 현재까지 이미 있는 것

아래 항목은 현재 코드베이스에 이미 들어와 있다.

- [x] reciprocal-shaped step circuit 추가
  - `crates/primitives/src/circuits/reciprocal_test.rs`
- [x] naive baseline 회로 추가
  - `crates/primitives/src/circuits/reciprocal_test.rs`
- [x] public/private object shell 추가
  - `crates/ivc/src/compilers/cyclefold/adapters/reciprocal_types.rs`
- [x] 4-coordinate wrapper + opening-aware proof path 추가
  - `crates/ivc/src/compilers/cyclefold/adapters/reciprocal_wrapper.rs`
- [x] adapter flattening 경계 추가
  - `crates/ivc/src/compilers/cyclefold/adapters/reciprocal.rs`
- [x] Nova + CycleFold integration test 추가
  - `crates/ivc/src/compilers/cyclefold/adapters/nova.rs`
- [x] stock / naive / specialized snapshot benchmark 추가
  - `crates/ivc/src/compilers/cyclefold/adapters/nova.rs`
- [x] 현재 PoC의 claim / non-claim 문서화
  - `docs/reciprocal_poc.md`

하지만 이 상태만으로는 아직 리뷰어가 지적한 핵심 간극이 남아 있다.

---

## 이번 PoC에서 반드시 추가해야 할 것

이 아래는 **grant-worthy PoC**를 위해 필요한 최소 필수 항목이다.

### 1. affine shape-test를 작은 "진짜 reciprocal kernel"로 교체

- [x] `ReciprocalCircuitForTest`가 더 이상 `y_i = q_i * x + bias_i` toy 회로가 아니어야 한다.
- [x] 아주 작은 `n`이라도 실제 reciprocal fold recurrence를 반영해야 한다.
- [x] `q`는 단순 `[F; 4]` 장난감 계수가 아니라, 실제 descriptor 의미를 가진 값이어야 한다.
- [x] out-of-circuit evaluator와 in-circuit 제약이 같은 recurrence를 계산해야 한다.

대상 파일:

- `crates/primitives/src/circuits/reciprocal_test.rs`

완료 기준:

- [x] 회로 주석에서 "small shape-test"라고만 말하지 않아도 된다.
- [x] 테스트가 "real reciprocal semantics for a tiny fixed instance"를 증명한다.
- [x] benchmark row의 `q_len`이 단순 placeholder 4가 아니라 실제 descriptor 선택과 연결된다.

범위 제한:

- 이번 단계에서 generic `n` 전체를 회로화할 필요는 없다.
- 작은 고정 인스턴스로도 충분하다.
- 중요한 것은 "이름만 reciprocal" 상태를 끝내는 것이다.

### 2. `y`를 테스트 하네스가 아니라 verifier-bound statement로 묶기

- [x] 현재 `external_outputs == expected_outputs`를 Rust 테스트 코드에서만 비교하는 구조를 넘어서야 한다.
- [x] 잘못된 `y`를 verifier 경로가 스스로 reject하는 테스트가 필요하다.
- [x] wrapper / adapter / verifier-visible object 중 적어도 한 경계에서는 `y`가 public statement로 실제 소비되어야 한다.

대상 파일:

- `crates/ivc/src/compilers/cyclefold/adapters/nova.rs`
- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal.rs`
- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal_wrapper.rs`

완료 기준:

- [x] "잘못된 `y`를 넣으면 verifier가 reject한다"는 독립 테스트가 있다.
- [x] `y`의 정합성이 더 이상 `assert_eq!` 보조 확인에만 의존하지 않는다.

범위 제한:

- 이번 단계에서 in-circuit decider까지 갈 필요는 없다.
- offchain verifier-bound rejection만 있어도 grant PoC에는 충분하다.

### 3. placeholder `Pi`를 최소한의 real proof object로 대체

- [x] `ReciprocalAggregatedProof`가 단순 coordinate tuple 저장소를 넘어서야 한다.
- [x] 적어도 하나의 실제 relation/opening 흐름이 prove/verify API 안에 들어가야 한다.
- [x] primitive는 일단 Pedersen-backed라도 괜찮다.

대상 파일:

- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal_wrapper.rs`
- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal.rs`
- 필요 시 새 helper 파일 추가

완료 기준:

- [x] 문서에서 `Pi`를 "placeholder"라고 부르지 않아도 된다.
- [x] proof object가 "(C, q, y)와 같은 x/descriptor에서 나왔다"는 것을 실제 검증 흐름으로 보여준다.

범위 제한:

- full KZG일 필요 없다.
- full extractability theorem까지 갈 필요 없다.
- 하지만 "proof 이름만 있고 실제 검증은 없음" 상태는 벗어나야 한다.

### 4. wrapper/adapter를 실제 step 흐름에 더 직접 연결

- [x] 지금의 reciprocal helper 계층이 독립 유틸이 아니라 실제 integration flow에서 소비되어야 한다.
- [x] `build_statement_in_lane` 또는 후속 API가 integration test 안에서 실제 경계 object로 쓰여야 한다.
- [x] same-`q` lane 정책과 malformed statement rejection이 end-to-end 테스트에서 드러나야 한다.

대상 파일:

- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal.rs`
- `crates/ivc/src/compilers/cyclefold/adapters/nova.rs`

완료 기준:

- [x] integration test가 단지 회로 출력 비교만 하지 않는다.
- [x] `(C, q, y, Pi)` 경계 object가 실제 prove/verify 흐름에서 한 번은 사용된다.

범위 제한:

- 이번 단계에서 `sonobe-fs` 내부의 full reciprocal folding scheme 구현까지 갈 필요는 없다.
- staging-aligned adapter 경계에서만 보여줘도 충분하다.

### 5. grant-facing benchmark를 "진짜 질문"에 맞게 한 번 더 정리

- [x] benchmark는 "state에 metadata를 싣지 않으면 가볍다"를 넘어서, "real reciprocal kernel + verifier-bound object"를 기준으로 다시 한 번 찍어야 한다.
- [x] 최소 비교 축은 아래 셋을 유지한다.
  - stock baseline
  - naive reciprocal baseline
  - specialized reciprocal PoC
- [x] benchmark 결과를 문서에서 과장 없이 해석해야 한다.

현재 구현 메모:

- 최신 snapshot은 ignored benchmark와 example runner 양쪽에서 재현된다.
- 문서에는 `state_width`, `step_witnesses`, `primary_constraints`,
  `adapter_public_inputs`를 구조적 신호로, 시간 열은 환경 의존적 수치로 분리해 적었다.
- 해석은 "specialized가 naive보다 왜 가벼운가"와 "specialized path가 추가로 어떤
  verifier-visible object surface를 드러내는가"에 맞춰 고정했다.

대상 파일:

- `crates/ivc/src/compilers/cyclefold/adapters/nova.rs`
- `docs/reciprocal_poc.md`
- `docs/reciprocal_snapshot.csv`

완료 기준:

- "specialized path가 naive보다 왜 나은가"가 숫자로 유지된다.
- 리뷰어가 "이 수치가 정확히 무엇을 보여주는지" 혼동하지 않게 문서화된다.

범위 제한:

- 이번 단계에서 full production benchmark harness는 필요 없다.
- grant-facing reproducible snapshot이면 충분하다.

### 6. claim 문구를 PoC 목표에 맞게 더 정교하게 다듬기

- [x] 문서가 "full reciprocal folding scheme"처럼 읽히지 않도록 유지해야 한다.
- [x] 대신 "algebraic backend + real PoC boundary + next grant milestone"이 분명히 읽혀야 한다.
- [x] `same-q`, `offchain`, `Pedersen-backed`, `not final KZG`, `not final FS`를 계속 명시해야 한다.

현재 구현 메모:

- PoC 소개 문단에 "grant-facing backend PoC"라는 위치를 명시했다.
- current claims 아래에 grant-scoped one-paragraph claim을 따로 두어 과장된 해석을 막았다.
- non-claims와 next milestone을 분리해, 현재 산출물과 다음 자금 사용처가 바로 구분되게 했다.

대상 파일:

- `docs/reciprocal_poc.md`
- 필요 시 `README.md`

완료 기준:

- 심사자가 현재 산출물과 다음 자금 사용처를 바로 구분할 수 있다.
- 코드와 문서 claim 범위가 서로 어긋나지 않는다.

---

## 있으면 좋은 것

이 아래는 있으면 설득력이 좋아지지만, 필수보다 우선순위는 낮다.

### 7. `tau -> q` 또는 descriptor expansion helper 추가

- [x] 현재 hard-coded `q`를 넘어서, 작은 fixed instance라도 descriptor expansion 경로를 코드에 드러내기
- [x] reduced descriptor vs uniform transcript를 주석이나 helper 이름으로 분명히 구분하기

현재 구현 메모:

- ambient quartic extension 원소 `tau` 자체를 아직 코드에 들고 있지는 않는다.
- 대신 worked `N=4` PoC에 필요한 정확한 algebraic seed data인 `mu_1`을 저장하고,
  note의 `c = 0` descriptor-update를 통해 reduced descriptor `q = mu_2`를 계산한다.
- `ReciprocalSeedDescriptorN4`는 `reduced_descriptor()`와
  `uniform_round_descriptors()`를 함께 제공해 reduced/uniform 구분을 코드 레벨에
  남긴다.

후보 파일:

- `crates/primitives/src/circuits/reciprocal_test.rs`
- 새 helper 모듈

### 8. minimal offchain decider skeleton 추가

- [x] current wrapper/adapter statement를 입력으로 받는 간단한 offchain decider helper 추가
- [x] relation check / statement shape check / same-`q` policy를 한 entry point에서 호출

현재 구현 메모:

- `ReciprocalOffchainDecider`는 현재 PoC statement를 직접 받아 검증한다.
- `decide()`는 worked `N=4` descriptor shape와 same-`q` lane 정책을 함께 본다.
- `decide_opening()`은 여기에 opening-aware reciprocal relation 검증까지 붙인다.
- 이 helper는 final SNARK decider가 아니라, 현재 grant PoC 경계를 한 함수에서
  소비하는 minimal offchain entry point다.

후보 파일:

- `crates/ivc/src/compilers/cyclefold/adapters/reciprocal_decider.rs`

### 9. example runner를 조금 더 grant demo 친화적으로 정리

- [x] 단일 명령으로 statement 생성, verification, snapshot 출력까지 보는 example 정리
- [x] reviewer가 코드를 다 읽지 않아도 PoC 흐름을 직접 돌려볼 수 있게 하기

현재 구현 메모:

- `cargo run -p sonobe-ivc --example reciprocal_poc`가 seed-descriptor로 회로를 만들고,
  opening-aware statement를 구성한 뒤, offchain decider를 통과시킨 다음 snapshot을 출력한다.
- reviewer는 내부 테스트 파일을 전부 읽지 않아도 현재 reciprocal PoC 경계를 직접 실행해볼 수 있다.

후보 파일:

- `examples/reciprocal_poc.rs`
- `docs/reciprocal_poc.md`

---

## 이번 PoC에서는 일부러 하지 않아도 되는 것

이 아래는 후속 milestone로 미뤄도 된다.

- [ ] full KZG backend
- [ ] final Fiat-Shamir / ROM / qROM theorem
- [ ] full committed-input extractability package
- [ ] `sonobe-fs` 내부 full reciprocal folding scheme integration
- [ ] final onchain decider
- [ ] ZK / hiding / EVM verifier

이 항목들은 중요하지만, **이번 grant를 따기 위한 최소 PoC의 필수 조건은 아니다.**

---

## 추천 구현 순서

실제 작업 순서는 아래가 가장 안전하다.

1. `ReciprocalCircuitForTest`를 작은 real reciprocal kernel로 교체
2. `y`를 verifier-bound statement로 묶는 rejection test 추가
3. placeholder `Pi`를 최소 real proof object로 교체
4. wrapper/adapter를 integration flow에 직접 연결
5. benchmark와 문서 claim 갱신

이 순서를 지키면:

- toy criticism을 먼저 제거하고
- verifier binding을 붙이고
- proof object를 실체화한 뒤
- benchmark를 다시 읽을 수 있게 만들 수 있다.

---

## PoC 완료 판정

이번 PoC는 아래 문장을 방어할 수 있으면 충분하다.

> "We implemented a Pedersen-backed, same-q, offchain reciprocal PoC on top of Sonobe staging. The PoC now includes a small real reciprocal kernel, a verifier-bound public object `(C, q, y, Pi)`, an end-to-end specialized-vs-naive comparison, and a clear path toward descriptor-consuming opening and decider work."

반대로 아래 문장은 아직 쓰면 안 된다.

- "We already implemented the final KZG-based reciprocal folding scheme."
- "We already solved Fiat-Shamir security."
- "We already integrated the full production backend into Sonobe."

---

## 한 줄 요약

이 코드베이스에서 다음으로 추가해야 할 것은 많아 보이지만, grant 기준 핵심은 사실 네 가지다.

- toy affine 회로를 small real reciprocal kernel로 바꾸기
- `y`를 verifier에 묶기
- `Pi`를 실제 proof object로 바꾸기
- specialized path의 의미를 benchmark와 문서로 방어하기
