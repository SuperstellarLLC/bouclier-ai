#!/usr/bin/env swift

import AppKit

// Generate app icon: shield with checkmark on dark background
func renderIcon(size: Int) -> NSImage {
    let img = NSImage(size: NSSize(width: size, height: size))
    img.lockFocus()

    let ctx = NSGraphicsContext.current!.cgContext
    let s = CGFloat(size)
    let padding = s * 0.15

    // Background rounded rect
    let bgRect = CGRect(x: 0, y: 0, width: s, height: s)
    let bgPath = NSBezierPath(roundedRect: bgRect, xRadius: s * 0.22, yRadius: s * 0.22)
    NSColor(red: 0.04, green: 0.04, blue: 0.04, alpha: 1).setFill()
    bgPath.fill()

    // Shield path (centered)
    let cx = s / 2
    let shieldTop = s - padding
    let shieldBottom = padding * 1.2
    let shieldWidth = s * 0.35
    let shieldMid = s * 0.48

    let shield = NSBezierPath()
    shield.move(to: NSPoint(x: cx, y: shieldTop))                          // top center
    shield.line(to: NSPoint(x: cx + shieldWidth, y: shieldTop - s * 0.12)) // top right
    shield.line(to: NSPoint(x: cx + shieldWidth, y: shieldMid))            // mid right
    shield.curve(to: NSPoint(x: cx, y: shieldBottom),                      // bottom center
                 controlPoint1: NSPoint(x: cx + shieldWidth, y: shieldMid - s * 0.15),
                 controlPoint2: NSPoint(x: cx + s * 0.12, y: shieldBottom + s * 0.05))
    shield.curve(to: NSPoint(x: cx - shieldWidth, y: shieldMid),           // mid left
                 controlPoint1: NSPoint(x: cx - s * 0.12, y: shieldBottom + s * 0.05),
                 controlPoint2: NSPoint(x: cx - shieldWidth, y: shieldMid - s * 0.15))
    shield.line(to: NSPoint(x: cx - shieldWidth, y: shieldTop - s * 0.12)) // top left
    shield.close()

    // Shield fill (subtle)
    NSColor(red: 0.13, green: 0.83, blue: 0.93, alpha: 0.1).setFill()
    shield.fill()

    // Shield stroke (cyan)
    NSColor(red: 0.13, green: 0.83, blue: 0.93, alpha: 1).setStroke()
    shield.lineWidth = s * 0.025
    shield.stroke()

    // Checkmark (green)
    let check = NSBezierPath()
    let checkScale = s * 0.15
    check.move(to: NSPoint(x: cx - checkScale * 0.9, y: shieldMid + checkScale * 0.1))
    check.line(to: NSPoint(x: cx - checkScale * 0.15, y: shieldMid - checkScale * 0.65))
    check.line(to: NSPoint(x: cx + checkScale * 1.1, y: shieldMid + checkScale * 0.9))

    NSColor(red: 0.13, green: 0.77, blue: 0.37, alpha: 1).setStroke()
    check.lineWidth = s * 0.04
    check.lineCapStyle = .round
    check.lineJoinStyle = .round
    check.stroke()

    img.unlockFocus()
    return img
}

func savePNG(_ image: NSImage, to path: String, size: Int) {
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: size, pixelsHigh: size,
        bitsPerSample: 8, samplesPerPixel: 4,
        hasAlpha: true, isPlanar: false,
        colorSpaceName: .deviceRGB,
        bytesPerRow: 0, bitsPerPixel: 0
    )!
    rep.size = NSSize(width: size, height: size)

    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    image.draw(in: NSRect(x: 0, y: 0, width: size, height: size))
    NSGraphicsContext.restoreGraphicsState()

    let data = rep.representation(using: .png, properties: [:])!
    try! data.write(to: URL(fileURLWithPath: path))
}

// Generate all sizes
let iconsetDir = "Ilvarion.iconset"
try? FileManager.default.createDirectory(atPath: iconsetDir, withIntermediateDirectories: true)

let sizes: [(name: String, px: Int)] = [
    ("icon_16x16", 16),
    ("icon_16x16@2x", 32),
    ("icon_32x32", 32),
    ("icon_32x32@2x", 64),
    ("icon_64x64", 64),
    ("icon_64x64@2x", 128),
    ("icon_128x128", 128),
    ("icon_128x128@2x", 256),
    ("icon_256x256", 256),
    ("icon_256x256@2x", 512),
    ("icon_512x512", 512),
    ("icon_512x512@2x", 1024),
]

for (name, px) in sizes {
    let icon = renderIcon(size: px)
    savePNG(icon, to: "\(iconsetDir)/\(name).png", size: px)
    print("Generated \(name).png (\(px)x\(px))")
}

print("Done. Run: iconutil -c icns Ilvarion.iconset -o Ilvarion.icns")
