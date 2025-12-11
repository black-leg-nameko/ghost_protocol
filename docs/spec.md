# Ghost: Ephemeral Network Persona (ENP) Protocol — Draft v0.2

## 0. 本文書の目的と用語

- 本仕様は、恒久IDを持たないノードが、時間スロットごとに生成する 人格＝Ghost で通信するオーバーレイを定義する。
- セッション継続は、相手対向にのみ検証可能なZK系継続証明（Designated-Verifier ZK） で行う。
- RFC 2119/RFC 8174 に従い、MUST/SHOULD/MAY を規範語とする。

## 1. 目標と非目標

**目標**

- 永続ID不使用。各ノードは Epoch ごとに Ghost = (sk_e, pk_e, meta_e) を生成。
- セッション継続は 相手対向だけ が検証可能。
- Non-transferability（第三者が検証できない）。
- 匿名レートリミットでDoS/スパム抑制。

**非目標**

- グローバル匿名性最適化
- 厳密リアルタイム保証

## 2. エンティティと時間

- Node: 実体。永続IDを持たない。
- Ghost: Epoch e における人格 (sk_e, pk_e, meta_e)。
- Epoch: 固定長区間 T 秒（推奨 300s）。
- Session: Ghost間の暗号化対話。

## 3. 脅威モデル

- ネットワーク観測者、MiTM、リプレイ、リレー妨害。
- 相手対向は継続を検証可能だが第三者は不可能。
- Sybil/スパム → 匿名トークンで制御。
- 秘密鍵流出 → 影響は当該Epochに限定。

## 4. クリプト選定（暫定）

- Group: Ristretto255
- KEX: X25519
- KDF: HKDF-SHA-512
- AEAD: ChaCha20-Poly1305
- Hash: SHA-512/256
- ZK継続証明: Designated-Verifier Schnorr (DV-Schnorr)

## 5. Ghost ライフサイクル

1. 生成: sk_e ←$ Z_q, pk_e = sk_e·G
2. アドレス: addr_e = H(pk_e || e)
3. 登録: DHT/メッシュに広告
4. 使用: セッション確立
5. 切替: e → e+1 で GhostRotate
6. 破棄: sk_e 消去

## 6. セッション確立

**メッセージ型（CBOR）**

```json
0x01 GHLO: {
  "ver": uint,
  "e": uint,
  "pk": bstr,
  "nonce": bstr,
  "kex": bstr,
  "suite": uint,
  "opts": map
}

0x02 GACK: {
  "e": uint,
  "pk": bstr,
  "nonce": bstr,
  "kex": bstr,
  "mac": bstr
}
```

**鍵派生**

- ss = DH(ephA, ephB)
- K_s = HKDF(ss, "sess", transcript)
- dvk = HKDF(K_s, "dvk", pk_A||pk_B||e)
- AEAD(K_data, …)

## 7. ZKベースのセッション継続（DV-Schnorr）

**Prover**

1. r1, r2 ←$ Z_q
2. t1 = r1·G, t2 = r2·G
3. c = H(dvk || "GHOST-ROTATE" || e_new || pk_old || pk_new || t1 || t2)
4. s1 = r1 + c·sk_old, s2 = r2 + c·sk_new
5. null = H(dvk || "NULL" || e_new)
6. 送信: ROTATE{e_old, e_new, pk_old, pk_new, t1, t2, c, s1, s2, null}

**Verifier**

1. c' = H(dvk || …)
2. 検証:
    - s1·G == t1 + c'·pk_old
    - s2·G == t2 + c'·pk_new
3. 
4. null 再利用チェック
5. OKなら pk_new に切替

## 8. ローテーション・メッセージ

```json
0x03 ROTATE: {
  "e_old": uint,
  "e_new": uint,
  "pk_old": bstr,
  "pk_new": bstr,
  "t1": bstr, "t2": bstr,
  "c": bstr, "s1": bstr, "s2": bstr,
  "null": bstr
}

0x04 RACK: {
  "e_new": uint,
  "ack": bool,
  "note": tstr?
}
```

## 9. オーバーレイルーティング

- アドレス: addr_e = H(pk_e || e)
- 広告: Advert{pk_e, e, expiry, budget_proof}
- スパム抑止: PoWまたは匿名トークン
- 転送: 任意輸送層（UDP/QUIC/TCP）

## 10. セキュリティサマリ

- リンク不能性: 第三者は pk_old と pk_new の関係を検証できない
- 否認可能性: 対向は検証できるが第三者へ証明不可
- 前方秘匿: 毎Epoch新鍵
- リプレイ対策: null
- Sybil防御: 匿名トークン＋PoW

## 11. 推奨パラメータ

- T = 300s
- Grace = 2T
- AEAD_RECORD_SIZE = 1200
- Advert_TTL = 3T

## 12. 疑似コード

```python
# Key derivation
K_s  = HKDF(ss, b"sess" + transcript)
dvk  = HKDF(K_s, b"dvk" + pkA + pkB + int_to_bytes(e))

# Prover
r1, r2 = randZq(), randZq()
t1, t2 = r1*G, r2*G
c  = H(dvk || "GHOST-ROTATE" || e_new || pk_old || pk_new || t1 || t2)
s1 = (r1 + c*sk_old) % q
s2 = (r2 + c*sk_new) % q
null = H(dvk || "NULL" || e_new)

ROTATE = {e_old, e_new, pk_old, pk_new, t1, t2, c, s1, s2, null}

# Verifier
c_ = H(dvk || …)
ok = (s1*G == t1 + c_*pk_old) and (s2*G == t2 + c_*pk_new)
```

## 13. 今後の課題

- DV-Schnorr の形式的安全性証明
- Epoch 非同期時のローテ挙動
- 匿名トークン発行モデル
- パディング・メタデータ隠蔽
 
## 14. 付録: ワイヤフォーマット/互換性（v0.2 追加）

本付録は v0.2 で導入された型付きエンベロープ、能力ネゴシエーション、バージョニング方針、CBOR後方互換ポリシーを定義する。従来の GHLO/GACK は将来の改訂で置換される予定（後方互換のため当面併記）。

### A. 型付きエンベロープ

すべてのメッセージは以下のエンベロープで輸送される。CBORは決定論的CBORを使用し、Mapキーは `uint` を採用する。

CDDL（抜粋。完全版は `docs/cddl/ghost-wire.cddl` を参照）:

```cddl
envelope = {
  0: env_ver: uint,        ; エンベロープスキーマ版（初期1）
  1: type_id: uint,        ; メッセージタイプID
  2: msg_ver: uint,        ; 当該タイプのメッセージ版
  3: msg_id: bstr .size 16,
  4: flags: uint,
  5: ts: uint,             ; ms since epoch
  6: body: any,
  ?7: auth: bstr,
  * uint => any
}
```

タイプID空間:
- 0: 無効
- 1..1023: コア予約（本仕様）
- 1024..16383: 将来コア予約
- 16384..32767: ベンダ/私用
- 32768..65535: 実験/一時

予約タイプID:
- 1: Capabilities
- 2: NegResult
- 3: Error

### B. 能力ネゴシエーション

目的はプロトコル版、機能集合、タイプ別メッセージ版レンジの合意。双方が `Capabilities` を送信し、イニシエータが `NegResult` を返す。交差が空なら `Error(code=1)`。

```cddl
capabilities = {
  0: proto_min: uint,                 ; major.minor を単一整数に符号化（例: major*1000+minor）
  1: proto_max: uint,
  2: features: [* uint],              ; 機能ID集合
  3: types: { * uint => [uint, uint] }, ; type_id => [min_ver, max_ver]
  ?4: params: { * uint => any },
  * uint => any
}

neg_result = {
  0: proto: uint,                     ; 合意プロトコル版
  1: features: [* uint],              ; 合意機能集合
  ?2: params: { * uint => any },
  * uint => any
}

error = {
  0: code: uint,                      ; 1=NegotiationFailed, 2=UnsupportedType, 3=VersionOutOfRange
  ?1: msg: tstr,
  * uint => any
}
```

### C. バージョニング方針

- 二層: プロトコル版（セッション/リンク全体: Major.Minor）と、タイプ別 `msg_ver`（非負整数）。
- Minorは後方互換の追加のみ（任意フィールド追加、意味不変）。破壊的変更は Major。
- 送信時は、相手が広告したレンジ内で可能な限り高い `msg_ver` を選ぶ。
- 既定値は明記し、Minorで変更しない。削除はDeprecatedを経て次のMajorで実施。

### D. CBORエンコーディング/後方互換

- 決定論的CBOR必須。Mapキーは `uint`。未知キーは受信側で無視（ignore-unknown）。
- 列挙の未知値は無視（must-understand を要する変更は Major）。
- 型変更（int→tstr 等）は Major でのみ可。浮動小数は必要時のみ64-bit、NaNは正規化。
- 時刻は `uint` のms固定。単位/エポックは変更不可。

