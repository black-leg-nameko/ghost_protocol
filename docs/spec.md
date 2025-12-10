# Ghost: Ephemeral Network Persona (ENP) Protocol — Draft v0.1

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


