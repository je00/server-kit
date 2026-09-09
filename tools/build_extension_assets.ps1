param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

# 生成扩展包图标和 Edge Add-ons 商店图标，避免发布时使用来源不明的素材。
Add-Type -AssemblyName System.Drawing

function New-RoundedRectangle {
    param([float]$X, [float]$Y, [float]$Width, [float]$Height, [float]$Radius)
    $path = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $diameter = $Radius * 2
    $path.AddArc($X, $Y, $diameter, $diameter, 180, 90)
    $path.AddArc($X + $Width - $diameter, $Y, $diameter, $diameter, 270, 90)
    $path.AddArc($X + $Width - $diameter, $Y + $Height - $diameter, $diameter, $diameter, 0, 90)
    $path.AddArc($X, $Y + $Height - $diameter, $diameter, $diameter, 90, 90)
    $path.CloseFigure()
    return $path
}

function New-ServerKitIcon {
    param([int]$Size, [string]$OutputPath)
    $bitmap = [System.Drawing.Bitmap]::new($Size, $Size)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $graphics.Clear([System.Drawing.Color]::Transparent)

    $scale = $Size / 128.0
    $background = New-RoundedRectangle (4 * $scale) (4 * $scale) (120 * $scale) (120 * $scale) (27 * $scale)
    $backgroundBrush = [System.Drawing.Drawing2D.LinearGradientBrush]::new(
        [System.Drawing.PointF]::new(12 * $scale, 8 * $scale),
        [System.Drawing.PointF]::new(116 * $scale, 120 * $scale),
        [System.Drawing.ColorTranslator]::FromHtml('#6D4AFF'),
        [System.Drawing.ColorTranslator]::FromHtml('#32246E')
    )
    $graphics.FillPath($backgroundBrush, $background)

    $shield = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $shield.AddLines([System.Drawing.PointF[]]@(
        [System.Drawing.PointF]::new(64 * $scale, 24 * $scale),
        [System.Drawing.PointF]::new(99 * $scale, 38 * $scale),
        [System.Drawing.PointF]::new(94 * $scale, 82 * $scale),
        [System.Drawing.PointF]::new(64 * $scale, 105 * $scale),
        [System.Drawing.PointF]::new(34 * $scale, 82 * $scale),
        [System.Drawing.PointF]::new(29 * $scale, 38 * $scale)
    ))
    $shield.CloseFigure()
    $shieldBrush = [System.Drawing.SolidBrush]::new([System.Drawing.Color]::FromArgb(230, 11, 18, 32))
    $graphics.FillPath($shieldBrush, $shield)

    $font = [System.Drawing.Font]::new('Segoe UI', 29 * $scale, [System.Drawing.FontStyle]::Bold, [System.Drawing.GraphicsUnit]::Pixel)
    $textBrush = [System.Drawing.SolidBrush]::new([System.Drawing.ColorTranslator]::FromHtml('#55F0C2'))
    $format = [System.Drawing.StringFormat]::new()
    $format.Alignment = [System.Drawing.StringAlignment]::Center
    $format.LineAlignment = [System.Drawing.StringAlignment]::Center
    $graphics.DrawString('SK', $font, $textBrush, [System.Drawing.RectangleF]::new(27 * $scale, 28 * $scale, 74 * $scale, 68 * $scale), $format)

    $directory = Split-Path -Parent $OutputPath
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $bitmap.Save($OutputPath, [System.Drawing.Imaging.ImageFormat]::Png)

    $format.Dispose()
    $textBrush.Dispose()
    $font.Dispose()
    $shieldBrush.Dispose()
    $shield.Dispose()
    $backgroundBrush.Dispose()
    $background.Dispose()
    $graphics.Dispose()
    $bitmap.Dispose()
}

$extensionRoot = Join-Path $RepositoryRoot 'browser_extension'
foreach ($size in 16, 32, 48, 128) {
    New-ServerKitIcon -Size $size -OutputPath (Join-Path $extensionRoot "icons/icon-$size.png")
}
New-ServerKitIcon -Size 300 -OutputPath (Join-Path $extensionRoot 'store-assets/logo-300.png')
Write-Host '已生成扩展图标和 Edge Add-ons 商店图标。'
