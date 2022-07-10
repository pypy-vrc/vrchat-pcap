const yus = require("yus");

const crc32Table = [
  0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
  0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
  0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
  0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
  0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
  0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
  0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
  0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
  0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
  0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
  0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
  0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
  0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
  0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
  0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
  0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
  0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
  0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
  0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
  0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
  0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
  0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
  0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
  0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
  0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
  0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
  0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
  0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
  0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
  0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
  0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
  0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
  0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
  0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
  0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
  0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
  0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
  0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
  0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
  0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
  0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
  0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
  0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
];

function calculateCrc(data, offset, length) {
  let crc = -1;

  for (let i = 0; i < length; ++i) {
    crc = crc32Table[(crc ^ data[offset + i]) & 255] ^ (crc >>> 8);
  }

  return crc >>> 0;
}

class StreamBuffer {
  constructor(buffer) {
    this.buffer = buffer;
    this.position = 0;
  }
  read(count) {
    const num = this.byteLength - this.position;
    if (num <= 0) {
      return null;
    }
    if (count > num) {
      count = num;
    }
    const data = this.buffer.slice(this.position, this.position + count);
    this.position += count;
    return data;
  }
  readByte() {
    if (this.position >= this.buffer.byteLength) {
      return -1;
    }
    const data = this.buffer.readUint8(this.position);
    ++this.position;
    return data;
  }
}

(function test() {
  // primeRoot = new BigInteger(OakleyGroups.Generator);
  // prime = new BigInteger(OakleyGroups.OakleyPrime768);
  // secret = GenerateRandomSecret(160);
  // const OakleyGroups.Generator = 22
  // const OakleyGroups.OakleyPrime768 = [
  //   255, 255, 255, 255, 255, 255, 255, 255, 201, 15, 218, 162, 33, 104, 194, 52,
  //   196, 198, 98, 139, 128, 220, 28, 209, 41, 2, 78, 8, 138, 103, 204, 116, 2,
  //   11, 190, 166, 59, 19, 155, 34, 81, 74, 8, 121, 142, 52, 4, 221, 239, 149,
  //   25, 179, 205, 58, 67, 27, 48, 43, 10, 109, 242, 95, 20, 55, 79, 225, 53,
  //   109, 109, 81, 194, 69, 228, 133, 181, 118, 98, 94, 126, 198, 244, 76, 66,
  //   233, 166, 58, 54, 32, 255, 255, 255, 255, 255, 255, 255, 255,
  // ];

  // clientPublicKey = primeRoot.ModPow(secret, prime);
  // 서버에 clientPublicKey 보냄
  // 클라는 serverPublicKey 받음
  // shardKey = serverPublicKey.ModPow(secret, prime);
  // aesKey = sha256(shardKey)

  // secret을 모르면 계산 불가;

  const clientPublicKey = Buffer.from(
    "8df3abeb6d45c0e5486dfaffcf74ca81c31a9883c68a07f6ae73e8400d8cbd9514e322d405855f27cda8a63630113dc6361748da3e5a92fb19e896835ea87997d38b050a2d6f627517445e5780e2c5a989068f5f2db7ed52af87d91f22f2394f",
    "hex"
  );
  const serverPublicKey = Buffer.from(
    "4ac756f5f5e2ce289cd4bbc35bf9ecfa5505dbc4af37757fce9b00dc4e1c2b1af5d65c09e4709ddad32ce17eb624af0a95616081fa16285c79d7ad0d6331bcb7c60edf045034ccdddd45f982b0c7dfd14b28e4ce11f6370a5d0f12ec44130e50",
    "hex"
  );
  console.log({ clientPublicKey, serverPublicKey });
})();

// keep node alive
setInterval(() => {}, 1000);

yus.yus((data) => {
  const raw = data.packet;
  let offset = 14; // length of ethernet header

  const saddr = `${raw.readUint8(offset + 12)}.${raw.readUint8(
    offset + 13
  )}.${raw.readUint8(offset + 14)}.${raw.readUint8(offset + 15)}`;
  const daddr = `${raw.readUint8(offset + 16)}.${raw.readUint8(
    offset + 17
  )}.${raw.readUint8(offset + 18)}.${raw.readUint8(offset + 19)}`;
  offset += (raw.readUint8(offset) & 15) * 4; // skip ip header

  const sport = raw.readUint16BE(offset);
  const dport = raw.readUint16BE(offset + 2);
  const packetLen = raw.readUint16BE(offset + 4) - 8;
  offset += 8; // skip udp header

  console.log(
    data.timestamp,
    `${saddr}:${sport} -> ${daddr}:${dport}, length=${packetLen}`
  );

  // 5055 Master Server
  // 5056 Game Server 1
  // 5057 Game Server 2

  try {
    parsePacket(raw, offset, packetLen);
  } catch (err) {
    console.error(err);
  }
});

function parsePacket(raw, offset, packetLen) {
  const peerId = raw.readUint16BE(offset);
  const b = raw.readUint8(offset + 2);
  if (b === 1) {
    console.error(
      "Got encrypted packet, but encryption is not set up. Packet ignored"
    );
    return;
  }

  const b2 = raw.readUint8(offset + 3);
  const serverSentTime = raw.readUint32BE(offset + 4);
  const challenge = raw.readUint32BE(offset + 8);

  console.log(
    `peerId=${peerId}, type=${b}, commands=${b2}, serverSentTime=${serverSentTime}, challenge=${challenge}`
  );

  if (b == 204) {
    const value3 = raw.readUint32BE(offset + 12);
    raw.writeUint32BE(0, offset + 12);
    const num = calculateCrc(raw, offset, packetLen);
    if (value3 !== num) {
      console.error(
        `Ignored package due to wrong CRC. Incoming: ${value3} Local: ${num}`
      );
      return;
    }
    offset += 16;
  } else {
    offset += 12;
  }

  if (b2 > 100 || b2 <= 0) {
    console.error(`too many/few incoming commands in package: ${b2} > 100`);
    return;
  }

  for (let i = 0; i < b2; ++i) {
    const command = {
      type: raw.readUint8(offset),
      channelId: raw.readUint8(offset + 1),
      flags: raw.readUint8(offset + 2),
      reservedByte: raw.readUint8(offset + 3),
      size: raw.readUint32BE(offset + 4),
      reliableSequenceNumber: raw.readUint32BE(offset + 8),
    };

    switch (command.type) {
      case 1: // CT_ACK
      case 16: // CT_EG_ACK_UNSEQUENCED
        command.ackReceivedReliableSequenceNumber = raw.readUint32BE(
          offset + 12
        );
        command.ackReceivedSentTime = raw.readUint32BE(offset + 16);
        break;

      case 2: // CT_CONNECT
        break;

      case 3: // CT_VERIFYCONNECT
        command.peerId = raw.readUint16BE(offset + 12);
        break;

      case 4: // CT_DISCONNECT
        // reservedByte
        // 1: DisconnectByServerLogic
        // 3: DisconnectByServerUserLimit
        // else: DisconnectByServer
        break;

      case 5: // CT_PING
        break;

      case 6: // CT_SENDRELIABLE
      case 14: // CT_EG_SEND_RELIABLE_UNSEQUENCED
        command.payload = raw.slice(offset + 12, offset + command.size);
        break;

      case 7: // CT_SENDUNRELIABLE
        command.unreliableSequenceNumber = raw.readUint32BE(offset + 12);
        command.payload = raw.slice(offset + 16, offset + command.size);
        break;

      case 8: // CT_SENDFRAGMENT
      case 15: // CT_EG_SEND_FRAGMENT_UNSEQUENCED
        startSequenceNumber = raw.readUint32BE(offset + 12);
        fragmentCount = raw.readUint32BE(offset + 16);
        fragmentNumber = raw.readUint32BE(offset + 20);
        totalLength = raw.readUint32BE(offset + 24);
        fragmentOffset = raw.readUint32BE(offset + 28);
        command.payload = raw.slice(offset + 32, offset + command.size);
        break;

      case 11: // CT_SENDUNSEQUENCED
        command.unsequencedGroupNumber = raw.readUint32BE(offset + 12);
        command.payload = raw.slice(offset + 16, offset + command.size);
        break;

      case 12: // CT_EG_SERVERTIME
        break;

      case 13: // CT_EG_SEND_UNRELIABLE_PROCESSED
        break;
    }

    offset += command.size;
    console.log(i, command);

    // FIXME
    // 패킷 fragments가 모두 모였을 경우 (fragmentsRemaining === 0)
    // value.Payload = array;
    // value.Size = 12 * value.fragmentCount + value.totalLength;
    // enetChannel.incomingReliableSequenceNumber = value.reliableSequenceNumber + value.fragmentCount - 1;

    if (command.payload !== void 0) {
      parseCommandPayload(command);
    }
  }
}

function parseCommandPayload(command) {
  const payload = command.payload;
  if (payload === void 0) {
    return;
  }

  if (payload.byteLength < 2) {
    console.error(`Incoming UDP data too short! ${payload.byteLength}`);
    return;
  }

  const b1 = payload.readUint8(0);
  if (b1 !== 243 && b1 !== 253) {
    console.error(`No regular operation UDP message: ${b1}`);
    return;
  }

  const b2 = payload.readUint8(1);
  const msgType = b2 & 127;
  const isEncrypted = b2 >= 128; // encryption

  console.log(`op=${b1}, msgType=${msgType}, isEncrypted=${isEncrypted}`);

  const streamBuffer = new StreamBuffer(command.payload.slice(2));

  if (isEncrypted) {
    console.error("encrypted payload, ignoring..");
    console.log(payload.toString("hex"));
    return;
  }

  switch (msgType) {
    case 0: // Init
      break;

    case 1: // InitResponse
      // InitCallback();
      break;

    case 2: // Operation
      const operationRequest = deserializeOperationRequest(streamBuffer);
      console.log("operationRequest", operationRequest);
      break;

    case 3: // OperationResponse
      // OperationResponse operationResponse = protocol.DeserializeOperationResponse(streamBuffer);
      // Listener.OnOperationResponse(operationResponse);
      const operationResponse = deserializeOperationResponse(streamBuffer);
      console.log("operationResponse", operationResponse);
      break;

    case 4: // Event
      const eventData = deserializeEventData(streamBuffer);
      console.log("eventData", eventData);
      // EventData eventData = protocol.DeserializeEventData(streamBuffer);
      // Listener.OnEvent(eventData);
      break;

    case 6: // InternalOperationRequest
      const internalOperationRequest =
        deserializeOperationRequest(streamBuffer);
      console.log("internalOperationRequest", internalOperationRequest);

      if (
        internalOperationRequest.operationCode ===
        /* PhotonCodes.InitEncryption */ 0
      ) {
        const key = internalOperationRequest.parameters.get(
          /* PhotonCodes.Client */ 1
        );
        if (key === void 0) {
          console.error(
            "Establishing encryption keys failed. Client's public key is null or empty."
          );
          break;
        }
        console.log("[ClientKey]", key.toString("hex"));
      }
      break;

    case 7: // InternalOperationResponse
      const internalOperationResponse =
        deserializeOperationResponse(streamBuffer);
      console.log("internalOperationResponse", internalOperationResponse);

      if (
        internalOperationResponse.operationCode ===
        /* PhotonCodes.InitEncryption */ 0
      ) {
        if (internalOperationResponse.returnCode !== 0) {
          console.error("Establishing encryption keys failed.");
          break;
        }
        const key = internalOperationResponse.parameters.get(
          /* PhotonCodes.ServerKey */ 1
        );
        if (key === void 0) {
          console.error(
            "Establishing encryption keys failed. Server's public key is null or empty."
          );
          break;
        }
        console.log("[ServerKey]", key.toString("hex"));
      }

      // internal static class PhotonCodes
      // {
      //     internal static byte ClientKey = 1;
      //     internal static byte ModeKey = 2;
      //     internal static byte ServerKey = 1;
      //     internal static byte InitEncryption = 0;
      //     internal static byte Ping = 1;
      //     public const byte Ok = 0;
      // }
      // OperationResponse operationResponse = protocol.DeserializeOperationResponse(streamBuffer);
      // if (operationResponse.OperationCode == PhotonCodes.InitEncryption)
      // {
      // 	DeriveSharedKey(operationResponse);
      // }
      // else if (operationResponse.OperationCode == PhotonCodes.Ping)
      // {
      // 	if (this is TPeer tPeer)
      // 	{
      // 		tPeer.ReadPingResult(operationResponse);
      // 	}
      // 	else
      // 	{
      // 		EnqueueDebugReturn(DebugLevel.ERROR, "Ping response not used. " + operationResponse.ToStringFull());
      // 	}
      // }
      break;

    case 8: // Message
      break;

    case 9: // RawMessage
      break;
  }
}

function read(stream, gpType) {
  if (gpType >= 128 && gpType <= 228) {
    return readCustomType(stream, gpType);
  }
  switch (gpType) {
    case 2:
      return readBoolean(stream);
    case 28:
      return true;
    case 27:
      return false;
    case 3:
      return readByte(stream);
    case 34:
      return /*(byte)*/ 0;
    case 4:
      return readInt16(stream);
    case 29:
      return /*(short)*/ 0;
    case 5:
      return readSingle(stream);
    case 32:
      return 0.0;
    case 6:
      return readDouble(stream);
    case 33:
      return 0.0;
    case 7:
      return readString(stream);
    case 11:
      return readInt1(stream, false);
    case 13:
      return readInt2(stream, false);
    case 12:
      return readInt1(stream, true);
    case 14:
      return readInt2(stream, true);
    case 9:
      return readCompressedInt32(stream);
    case 30:
      return 0;
    case 15:
      return /*(long)*/ readInt1(stream, false);
    case 17:
      return /*(long)*/ readInt2(stream, false);
    case 16:
      return /*(long)*/ readInt1(stream, true);
    case 18:
      return /*(long)*/ readInt2(stream, true);
    case 10:
      return readCompressedInt64(stream);
    case 31:
      return 0;
    case 21:
      return readHashtable(stream);
    case 20:
      return readDictionary(stream);
    case 19:
      return readCustomType(stream, 0);
    case 24:
      return deserializeOperationRequest(stream);
    case 25:
      return deserializeOperationResponse(stream);
    case 26:
      return deserializeEventData(stream);
    case 23:
      return readObjectArray(stream);
    case 66:
      return readBooleanArray(stream);
    case 67:
      return readByteArray(stream);
    case 68:
      return readInt16Array(stream);
    case 70:
      return readDoubleArray(stream);
    case 69:
      return readSingleArray(stream);
    case 71:
      return readStringArray(stream);
    case 85:
      return readHashtableArray(stream);
    case 84:
      return readDictionaryArray(stream);
    case 83:
      return readCustomTypeArray(stream);
    case 73:
      return readCompressedInt32Array(stream);
    case 74:
      return readCompressedInt64Array(stream);
    case 64:
      return readArrayInArray(stream);
  }

  return null;
}

function readBoolean(stream) {
  return stream.readByte() !== 0;
}

function readByte(stream) {
  return stream.readByte();
}

function readInt16(stream) {
  return stream.read(2).readInt16BE(0);
}

function readUshort(stream) {
  return stream.read(2).readUint16BE(0);
}

function readInt32(stream) {
  return stream.read(4).readInt32BE(0);
}

function readInt64(stream) {
  return stream.read(8).readBigInt64BE(0);
}

function readSingle(stream) {
  return stream.read(4).readFloat32BE(0);
}

function readDouble(stream) {
  return stream.read(8).readDouble32BE(0);
}

function readByteArray(stream) {
  return stream.read(readCompressedUint32(stream));
}

function readCustomType(stream, gpType) {
  const b = gpType !== 0 ? gpType - 128 : stream.readByte();
  return {
    customType: b,
    data: stream.read(readCompressedUint32(stream)),
  };
}

function deserializeEventData(stream) {
  return {
    code: readByte(stream),
    parameters: readParameterTable(stream),
  };
}

function readParameterTable(stream) {
  const map = new Map();
  const num = readByte(stream);
  for (let i = 0; i < num; ++i) {
    const key = stream.readByte();
    const value = read(stream, stream.readByte());
    map.set(key, value);
  }
  return map;
}

function readHashtable(stream) {
  const map = new Map();
  const num = readCompressedUint32(stream);
  for (let i = 0; i < num; ++i) {
    const key = read(stream, stream.readByte());
    const value = read(stream, stream.readByte());
    map.set(key, value);
  }
  return map;
}

function readIntArray(stream) {
  const array = [];
  const num = readInt32(stream);
  for (let i = 0; i < num; ++i) {
    array.push(readInt32(stream));
  }
  return array;
}

function deserializeOperationRequest(stream) {
  return {
    operationCode: readByte(stream),
    parameters: readParameterTable(stream),
  };
}

function deserializeOperationResponse(stream) {
  return {
    operationCode: readByte(stream),
    returnCode: readInt16(stream),
    debugMessage: read(stream, readByte(stream)),
    parameters: readParameterTable(stream),
  };
}

function readString(stream) {
  const num = readCompressedUint32(stream);
  if (num === 0) {
    return ""; // empty string
  }
  return stream.read(num).toString("utf8");
}

function readCustomTypeArray(stream) {
  const array = [];
  const num = readCompressedUint32(stream);
  const b = stream.readByte();
  for (let i = 0; i < num; ++i) {
    array.push({
      customType: b,
      data: stream.read(readCompressedUint32(stream)),
    });
  }
  return array;
}

function getDictArrayType(stream) {
  let gpType = stream.readbyte();
  while (gpType === /* GpType.Array */ 64) {
    gpType = stream.readbyte();
  }
}

function readDictionaryType(stream) {
  const keyReadType = stream.readByte();
  let valueReadType = stream.readByte();
  switch (valueReadType) {
    case 0: // GpType.Unknown
      // type2 = typeof(object);
      break;

    case 20: // GpType.Dictionary
      ({ valueReadType } = readDictionaryType(stream));
      break;

    case 64: // GpType.Array
      GetDictArrayType(stream);
      valueReadType = 0; // GpType.Unknown
      break;

    case 23: // GpType.ObjectArray
      // type2 = typeof(object[]);
      break;

    case 85: // GpType.HashtableArray
      // type2 = typeof(ExitGames.Client.Photon.Hashtable[]);
      break;

    default:
      // type2 = GetClrArrayType(gpType);
      break;
  }
  return {
    keyReadType,
    valueReadType,
  };
}

function readDictionary(stream) {
  const { keyReadType, valueReadType } = readDictionaryType(stream);
  return readDictionaryElements(stream, keyReadType, valueReadType);
}

function readDictionaryElements(stream, keyReadType, valueReadType) {
  const keyFlag = keyReadType === 0;
  const valueFlag = valueReadType === 0;
  const map = new Map();
  const num = readCompressedUint32(stream);
  for (let i = 0; i < num; ++i) {
    const key = read(stream, keyFlag ? stream.readByte() : keyReadType);
    const value = read(stream, valueFlag ? stream.readByte() : valueReadType);
    map.set(key, value);
  }
  return map;
}

function readObjectArray(stream) {
  const array = [];
  const num = readCompressedUint32(stream);
  for (let i = 0; i < num; ++i) {
    array.push(read(stream, stream.readByte()));
  }
  return array;
}

function readBooleanArray(stream) {
  const array = [];
  const num = readCompressedUint32(stream);
  let num2 = Math.floor(num / 8);
  let num3 = 0;
  while (num2 > 0) {
    const b = stream.readByte();
    array[num3++] = (b & 1) === 1;
    array[num3++] = (b & 2) === 2;
    array[num3++] = (b & 4) === 4;
    array[num3++] = (b & 8) === 8;
    array[num3++] = (b & 0x10) === 16;
    array[num3++] = (b & 0x20) === 32;
    array[num3++] = (b & 0x40) === 64;
    array[num3++] = (b & 0x80) === 128;
    --num2;
  }
  if (num3 < num) {
    const boolMasks = [1, 2, 4, 8, 16, 32, 64, 128];
    const b2 = stream.readByte();
    let num4 = 0;
    while (num3 < num) {
      array[num3++] = (b2 & boolMasks[num4]) === boolMasks[num4];
      ++num4;
    }
  }
  return array;
}

function readInt16Array(stream) {
  const array = [];
  const num = readCompressedUint32(stream);
  for (let i = 0; i < num; ++i) {
    array.push(readInt16(stream));
  }
  return array;
}

function readSingleArray(stream) {
  const array = [];
  const num = readCompressedUint32(stream);
  for (let i = 0; i < num; ++i) {
    array.push(readSingle(stream));
  }
  return array;
}

function readDoubleArray(stream) {
  const array = [];
  const num = readCompressedUint32(stream);
  for (let i = 0; i < num; ++i) {
    array.push(readDouble(stream));
  }
  return array;
}

function readStringArray(stream) {
  const array = [];
  const num = readCompressedUint32(stream);
  for (let i = 0; i < num; ++i) {
    array.push(readString(stream));
  }
  return array;
}

function readHashtableArray(stream) {
  const array = [];
  const num = readCompressedUint32(stream);
  for (let i = 0; i < num; ++i) {
    array.push(readHashtable(stream));
  }
  return array;
}

function readDictionaryArray(stream) {
  const { keyReadType, valueReadType } = readDictionaryType(stream);
  const array = [];
  const num = readCompressedUint32(stream);
  for (let i = 0; i < num; ++i) {
    array.push(readDictionaryElements(stream, keyReadType, valueReadType));
  }
  return array;
}

function readArrayInArray(stream) {
  const array = [];
  const num = readCompressedUint32(stream);
  for (let i = 0; i < num; ++i) {
    array.push(read(stream, stream.readByte()));
  }
  return array;
}

function readInt1(stream, signNegative = false) {
  if (signNegative) {
    return -stream.readByte();
  }
  return stream.readByte();
}

function readInt2(stream, signNegative = false) {
  if (signNegative) {
    return -readUshort(stream);
  }
  return readUshort(stream);
}

function readCompressedInt32(stream) {
  return decodeZigZag32(readCompressedUint32(stream));
}

function readCompressedUint32(stream) {
  let num = 0;
  let position = stream.position;
  for (let i = 0; i < 35; i += 7) {
    const b = stream.buffer[position];
    ++position;
    num |= (b & 127) << i;
    if (b < 128) {
      break;
    }
  }
  stream.position = position;
  return num;
}

function readCompressedInt64(stream) {
  return decodeZigZag64(readCompressedUint64(stream));
}

function readCompressedUint64(stream) {
  let num = 0n;
  let position = stream.position;
  for (let i = 0; i < 70; i += 7) {
    const b = stream.buffer[position];
    ++position;
    num |= (b & 127) << i;
    if (b < 128) {
      break;
    }
  }
  stream.position = position;
  return num;
}

function readCompressedInt32Array(stream) {
  const array = [];
  const num = readCompressedUint32(stream);
  for (let i = 0; i < num; ++i) {
    array.push(readCompressedInt32(stream));
  }
  return array;
}

function readCompressedInt64Array(stream) {
  const array = [];
  const num = readCompressedUint32(stream);
  for (let i = 0; i < num; ++i) {
    array.push(readCompressedInt64(stream));
  }
  return array;
}

function decodeZigZag32(value) {
  return (value >>> 1) ^ (0 - (value & 1));
}

function decodeZigZag64(value) {
  return (value >>> 1) ^ (0n - (value & 1n));
}

// Unknown = 0,
// Boolean = 2,
// Byte = 3,
// Short = 4,
// Float = 5,
// Double = 6,
// String = 7,
// Null = 8,
// CompressedInt = 9,
// CompressedLong = 10,
// Int1 = 11,
// Int1_ = 12,
// Int2 = 13,
// Int2_ = 14,
// L1 = 15,
// L1_ = 16,
// L2 = 17,
// L2_ = 18,
// Custom = 19,
// CustomTypeSlim = 128,
// Dictionary = 20,
// Hashtable = 21,
// ObjectArray = 23,
// OperationRequest = 24,
// OperationResponse = 25,
// EventData = 26,
// BooleanFalse = 27,
// BooleanTrue = 28,
// ShortZero = 29,
// IntZero = 30,
// LongZero = 31,
// FloatZero = 32,
// DoubleZero = 33,
// ByteZero = 34,
// Array = 64,
// BooleanArray = 66,
// ByteArray = 67,
// ShortArray = 68,
// DoubleArray = 70,
// FloatArray = 69,
// StringArray = 71,
// HashtableArray = 85,
// DictionaryArray = 84,
// CustomTypeArray = 83,
// CompressedIntArray = 73,
// CompressedLongArray = 74
