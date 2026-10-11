'use strict';
/* 加入证明 v2（web/core.js）：链路上不再出现房间密钥本身。
   断言用 node:crypto 独立实现 HKDF/HMAC 交叉核对，不只信 core.js 自己的输出。 */
const {test}=require('node:test'),assert=require('node:assert/strict'),{createHmac}=require('node:crypto');
if(!global.crypto)global.crypto=require('node:crypto').webcrypto;
const C=require('../../web/core.js');

const SECRET='a-reusable-room-secret-please-do-not-leak', ROOM='房间-🌏';

function hkdfSha256(ikm,salt,info,length){          // RFC 5869，独立实现
  const prk=createHmac('sha256',salt).update(ikm).digest();
  let okm=Buffer.alloc(0),block=Buffer.alloc(0),counter=1;
  while(okm.length<length){
    block=createHmac('sha256',prk).update(Buffer.concat([block,info,Buffer.from([counter])])).digest();
    okm=Buffer.concat([okm,block]);counter+=1;
  }
  return okm.subarray(0,length);
}
const expectedKey=hex=>hkdfSha256(Buffer.from(SECRET,'utf8'),Buffer.from(ROOM,'utf8'),
                                 Buffer.from('p2pchat/join-key/v2','utf8'),32).toString('hex');
const expectedProof=(keyHex,nonce,session)=>createHmac('sha256',Buffer.from(keyHex,'hex'))
  .update(Buffer.from(`${ROOM}\u0000${nonce}\u0000${session}`,'utf8')).digest('hex');

test('加入密钥是 HKDF 派生值，且不等于房间密钥本身',async()=>{
  const key=await C.joinKey(SECRET,ROOM);
  assert.match(key,/^[0-9a-f]{64}$/);
  assert.equal(key,expectedKey());                      // 与独立 HKDF 实现一致
  assert.notEqual(key,SECRET);
  assert.ok(!key.includes(SECRET));
  assert.equal(C.JOIN.version,2);
  assert.equal(C.JOIN.proof,'hkdf-sha256-hmac-v2');
});

test('加入证明是 nonce 绑定的 HMAC，换 nonce/会话/房间都会变',async()=>{
  const key=await C.joinKey(SECRET,ROOM);
  const proof=await C.joinProof(key,ROOM,'n'.repeat(48),'session-1');
  assert.match(proof,/^[0-9a-f]{64}$/);
  assert.equal(proof,expectedProof(key,'n'.repeat(48),'session-1'));
  assert.notEqual(proof,await C.joinProof(key,ROOM,'n'.repeat(47)+'m','session-1'));
  assert.notEqual(proof,await C.joinProof(key,ROOM,'n'.repeat(48),'session-2'));
  assert.notEqual(proof,await C.joinProof(key,'另一个房间','n'.repeat(48),'session-1'));
  assert.notEqual(proof,await C.joinKey(SECRET+'x',ROOM)&&await C.joinProof(await C.joinKey(SECRET+'x',ROOM),ROOM,'n'.repeat(48),'session-1'));
});

test('join 报文里没有房间密钥，只有派生值与一次性证明',async()=>{
  const nonce='ab'.repeat(24),session='11111111-1111-1111-1111-111111111111';
  const fresh=await C.joinMessage({room:ROOM,secret:SECRET,name:'alice',clientSessionId:session,
    capabilities:['webrtc'],nonce,roomEstablished:false});
  assert.equal(fresh.v,1);
  assert.equal(fresh.type,'join');
  assert.equal(fresh.joinVersion,2);
  assert.equal(fresh.nonce,nonce);
  assert.equal(fresh.proof,expectedProof(await C.joinKey(SECRET,ROOM),nonce,session));
  assert.equal(fresh.verifier,await C.joinKey(SECRET,ROOM));   // 房间还是新的：交派生值建立房间密钥
  assert.equal('secret' in fresh,false);                       // 关键：报文里绝不出现 secret
  const wire=JSON.stringify(fresh);
  assert.ok(!wire.includes(SECRET));
  assert.ok(!/"(secret|roomKey)"\s*:/.test(wire));

  const established=await C.joinMessage({room:ROOM,secret:SECRET,name:'bob',clientSessionId:session,
    capabilities:['webrtc'],nonce,roomEstablished:true});
  assert.equal('verifier' in established,false);               // 房间已有密钥：不再交任何派生值
  assert.ok(!JSON.stringify(established).includes(SECRET));
});

test('没有 nonce 就不构造加入证明，也不存在回退到明文密钥的路径',async()=>{
  const message=await C.joinMessage({room:ROOM,secret:SECRET,name:'alice',clientSessionId:'s',
    capabilities:['webrtc'],nonce:undefined,roomEstablished:false});
  assert.equal(message.nonce,undefined);                       // 由服务器直接拒绝，而不是退回 v1
  assert.equal('secret' in message,false);
  assert.equal(typeof C.joinMessage,'function');
});

test('挑战报文只带房间与会话，不带任何密钥材料',()=>{
  const message=C.joinChallengeMessage(ROOM,'session-1');
  assert.deepEqual(message,{v:1,type:'join_challenge',room:ROOM,clientSessionId:'session-1'});
  assert.ok(!JSON.stringify(message).includes(SECRET));
});
