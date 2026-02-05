# Create a minimal valid ICO file for Tauri
Add-Type -AssemblyName System.Drawing

# Create a 32x32 bitmap with a simple design
$bmp = New-Object System.Drawing.Bitmap(32, 32)
$graphics = [System.Drawing.Graphics]::FromImage($bmp)

# Fill with a blue background
$brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::DodgerBlue)
$graphics.FillRectangle($brush, 0, 0, 32, 32)

# Draw a white phone icon (simplified)
$pen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 3)
$graphics.DrawArc($pen, 8, 8, 16, 16, 0, 360)

# Clean up
$graphics.Dispose()
$brush.Dispose()
$pen.Dispose()

# Save as PNG first
$pngPath = "crates\client\client-gui-tauri\icons\icon.png"
$bmp.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png)

# Convert to ICO
$icoPath = "crates\client\client-gui-tauri\icons\icon.ico"
$icon = [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
$stream = [System.IO.File]::Create($icoPath)
$icon.Save($stream)
$stream.Close()

# Clean up
$bmp.Dispose()
$icon.Dispose()

Write-Host "Icon created successfully at $icoPath"
