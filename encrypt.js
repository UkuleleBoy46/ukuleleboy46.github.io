var Crypto = {
  blockSize: 128,
  keySize: 256,
  iterations: 2048,
  encrypt: function(msg, secret, sign) {
    // Generate IV (16 Bytes)
    var iv = CryptoJS.lib.WordArray.random(this.blockSize / 8);

    // Generate salt (16 Bytes)
    var salt = CryptoJS.lib.WordArray.random(this.blockSize / 8);

    // Generate key
    var key = this.generateKey(secret, salt);

    // Encrypt
    var encrypted = CryptoJS.AES.encrypt(
      msg,
      key,
      {
        iv: iv,
        padding: CryptoJS.pad.Pkcs7,
        mode: CryptoJS.mode.CBC
      }
    );

    // Encode (iv + salt + payload)
    var ciphertext64 = this.base64UrlEncode(
      atob(CryptoJS.enc.Base64.stringify(iv)) +
      atob(CryptoJS.enc.Base64.stringify(salt)) +
      atob(encrypted.toString())
    );

    // Sign
    if (sign) {
      ciphertext64 = ciphertext64 + ":" + this.sign(ciphertext64, key);
    }

    return ciphertext64;
  },
  generateKey: function(secret, salt) {
    return CryptoJS.PBKDF2(
      secret,
      salt,
      {
        keySize: this.keySize / 32, // size in Words
        iterations: this.iterations,
        hasher: CryptoJS.algo.SHA1
      }
    );
  }