
Set-Location "F:\skibidi"
g++ khkt.cpp sha256.cpp aes.cpp hmac_sha256.cpp -o khkt.exe -laubio

if ($LASTEXITCODE -eq 0) {
    Write-Host "--- BIEN DICH THANH CONG! ---" -ForegroundColor Green
    .\khkt.exe
} else {
    Write-Host "--- LOI BIEN DICH! ---" -ForegroundColor Red
}