import sys
import hmac
import hashlib
import time
import qrcode

def is_hexadecimal(s):
   for char in s:
      if not char.isalnum(): # Check if the character is a valid hexadecimal digit
         return False
   return True

def GenTOTP(pvt_key):

    epoch_time = int(time.time() / 30)
    timeKEY = bytes.fromhex(pvt_key) + str(epoch_time).encode('utf-8')
    new_key = hmac.new(bytes.fromhex(pvt_key), timeKEY, hashlib.sha256).hexdigest()
    key_hmac_bytes = bytes.fromhex(new_key)
    offset = key_hmac_bytes[19] & 0xf

    bin_code = (key_hmac_bytes[offset] & 0x7f) << 24 | (key_hmac_bytes[offset + 1] & 0xff) << 16 | (key_hmac_bytes[offset + 2] & 0xff) << 8 | (key_hmac_bytes[offset + 3] & 0xff)
    
    _totp = int(bin_code) % 1000000
    totp = f'{_totp:06}'
    print(f"TOTP : {totp}")
    qr = qrcode.QRCode(version=3, box_size=20, border=10, error_correction=qrcode.constants.ERROR_CORRECT_H)

    # Define the data to be encoded in the QR code
    data = "https://api.qrserver.com/v1/create-qr-code/?secret=" + new_key + "&issuer=" + "mytotp&algorithm=SHA256&digits=6&period=30"

    # otpauth://totp/MonService:nom.d.utilisateur?secret=JBSWY3DPEHPK3PXP&issuer=MonService&algorithm=SHA1&digits=6&period=30

    # Add the data to the QR code object
    qr.add_data(data)

    # Make the QR code
    qr.make(fit=True)

    # Create an image from the QR code with a black fill color and white background
    img = qr.make_image(fill_color="black", back_color="white")

    # Save the QR code image
    img.save("qr_code.png")

def GenKey(hexKey):
    if (len(hexKey) != 32):
        sys.exit()

    new_key = hashlib.sha256(bytes.fromhex(hexKey)).hexdigest()

    f = open("ft_otp.key", "a")
    f.truncate(0)
    f.write(new_key)
    f.close()

    print("Key generate")
    return new_key

if __name__ == '__main__':
    try:
        if (sys.argv[1] == "-g"):
            with open(sys.argv[2], 'r') as file:
                hexKey = file.read().strip() # .strip() = delete \n
            key_hmac = GenKey(hexKey)
        elif (sys.argv[1] == "-k"):
            with open(sys.argv[2], 'r') as file:
                pvt_key = file.read().strip()
            GenTOTP(pvt_key)
    except:
        sys.exit("Error\n-g <hex_key.txt>\n-k <ft_totp.key>")
    