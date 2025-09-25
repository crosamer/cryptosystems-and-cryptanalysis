# Cryptosystem Web Application

Aplikasi web minimalis berbasis Flask untuk enkripsi dan dekripsi menggunakan algoritma cipher klasik. Mendukung input teks maupun file (teks/biner), validasi/generasi kunci, batch encrypt (ZIP), serta analisis frekuensi huruf.

## Link Repository (Publik)
- https://github.com/crosamer/cryptosystems-and-cryptanalysis

## Fitur Utama

### Algoritma Cipher yang Didukung
1. Shift Cipher (Caesar)
2. Substitution Cipher
3. Affine Cipher
4. Vigenere Cipher
5. Hill Cipher (2x2)
6. Permutation Cipher (Columnar Transposition)
7. Playfair Cipher
8. One-Time Pad (OTP) berbasis file kunci

### Kapabilitas
- Enkripsi/dekripsi teks langsung dari textarea
- Enkripsi/dekripsi file sembarang (teks/biner) dengan pelestarian metadata
- Tampilan cipherteks: tanpa spasi dan kelompok 5 huruf
- Simpan hasil enkripsi ke file .dat
- Batch encrypt (multi-file → ZIP)
- Analisis frekuensi teks

## Cara Menjalankan (Windows/PowerShell)

1) Pastikan terpasang:
- Python 3.9+ (teruji juga di 3.13)
- pip

2) (Opsional) Buat virtual environment
```bash
python -m venv .venv
. .venv\Scripts\Activate.ps1
```

3) Install dependensi
```bash
pip install -r requirements.txt
```
Jika menggunakan Python 3.13 dan terjadi error instalasi NumPy, gunakan:
```bash
pip install Flask==2.3.3 numpy Werkzeug==2.3.7
```

4) Jalankan aplikasi
```bash
python app.py
```
Buka browser ke:
- http://127.0.0.1:5000

## Cara Menggunakan Aplikasi
- Pilih algoritma cipher
- Masukkan kunci (gunakan tombol Generate/Validate bila perlu)
- Pilih metode input:
  - Text Input: ketik plaintext (Encrypt) atau ciphertext (Decrypt)
  - File Upload: unggah file untuk dienkripsi
  - Decrypt File: unggah file .dat hasil aplikasi ini untuk didekripsi
- Klik Encrypt/Decrypt
- Untuk file, tombol Download akan muncul setelah proses selesai
- Untuk OTP, buat kunci via tombol Generate OTP Key → kolom kunci diisi `file:nama_file.txt`

## Format Kunci Singkat
- Shift: angka 0–25
- Substitution: 26 huruf unik (A–Z)
- Affine: dua bilangan a,b dengan gcd(a,26)=1, contoh "5,8"
- Vigenere: huruf saja (A–Z)
- Hill: empat bilangan untuk matriks 2x2, contoh "3,2,5,7" (determinan koprima 26)
- Permutation: kata kunci huruf (A–Z)
- Playfair: kata kunci huruf (J disatukan dengan I)
- One-Time Pad: `file:nama_file.txt` untuk membaca kunci dari folder `keys/`

## Penanganan File
- Semua jenis file dapat dienkripsi; seluruh byte (termasuk header) ikut terenkripsi
- Hasil enkripsi disimpan sebagai `.dat` beserta metadata (nama/ekstensi/mime asli)
- Saat dekripsi, file biner direstorasi sehingga dapat dibuka kembali oleh aplikasinya

## Batch Encrypt
- Endpoint `/batch_encrypt` mendukung unggah beberapa file sekaligus dan menghasilkan paket ZIP untuk diunduh

## Struktur Proyek (ringkas)
- `app.py` – endpoint Flask
- `ciphers/` – implementasi cipher
- `utils/file_processor.py` – baca/tulis file, metadata, paket ZIP, restore biner
- `utils/crypto_utils.py` – validasi/generasi kunci, analisis frekuensi
- `templates/` – antarmuka web
- `uploads/`, `encrypted/`, `temp/`, `keys/` – folder kerja

## Troubleshooting
- Error NumPy pada Python 3.13:
  - Gunakan: `pip install Flask==2.3.3 numpy Werkzeug==2.3.7`
- Pesan "No input provided" saat dekripsi teks:
  - Pastikan memilih "Text Input" dan menempelkan ciphertext di textarea
- OTP gagal:
  - Pastikan panjang kunci ≥ panjang pesan; gunakan format `file:nama_key.txt`
- 404 favicon.ico di log:
  - Diabaikan (tidak mempengaruhi fungsionalitas)

## Catatan/Keterbatasan
- Hill Cipher yang disediakan untuk matriks 2x2
- Mode teks klasik memang hanya memproses huruf A–Z (angka/spasi/tanda baca dibuang) sesuai ketentuan
- Untuk file sembarang, byte diubah ke representasi teks saat enkripsi dan direstorasi saat dekripsi

## Status Pengerjaan
- Aplikasi berjalan dan memenuhi ketentuan utama (lihat fitur)

## Lisensi
Untuk keperluan akademik/kuliah kriptografi.
