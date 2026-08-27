# Repairs XAMPP MariaDB when it hangs or fails with "Failed to initialize multi master structures".
# Corrupted master-*.info / relay-log-* files in the data directory cause this.

$ErrorActionPreference = "Stop"
$MysqlBin = "C:\xampp\mysql\bin"
$DataDir = "C:\xampp\mysql\data"

Write-Host "Stopping MySQL..."
Get-Process mysqld, mysql -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$masters = @(Get-ChildItem "$DataDir\master-*" -ErrorAction SilentlyContinue)
$relays = @(Get-ChildItem "$DataDir\relay-log-*" -ErrorAction SilentlyContinue)
Write-Host "Removing $($masters.Count) master-* and $($relays.Count) relay-log-* files..."
Remove-Item "$DataDir\master-*" -Force -ErrorAction SilentlyContinue
Remove-Item "$DataDir\relay-log-*" -Force -ErrorAction SilentlyContinue
Remove-Item "$DataDir\multi-master.info" -Force -ErrorAction SilentlyContinue

Write-Host "Starting MySQL..."
Start-Process -FilePath "$MysqlBin\mysqld.exe" -ArgumentList "--defaults-file=$MysqlBin\my.ini" -WindowStyle Hidden
Start-Sleep -Seconds 10

& "$MysqlBin\mysql.exe" -h 127.0.0.1 -uroot -e "SELECT 1 AS ok;" 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "MySQL is ready."
} else {
    Write-Host "MySQL did not start. Check C:\xampp\mysql\data\mysql_error.log"
    exit 1
}
