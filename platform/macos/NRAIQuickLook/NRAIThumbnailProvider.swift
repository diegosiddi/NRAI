import AppKit
import QuickLookThumbnailing

@objc(NRAIThumbnailProvider)
final class NRAIThumbnailProvider: QLThumbnailProvider {
    override func provideThumbnail(
        for request: QLFileThumbnailRequest,
        _ handler: @escaping (QLThumbnailReply?, Error?) -> Void
    ) {
        do {
            let payload = try NRAIV1.verifiedPayload(from: request.fileURL, forThumbnail: true)
            guard let image = NSImage(data: payload) else { throw NRAIError.invalidManifest("image payload") }
            let size = request.maximumSize
            let reply = QLThumbnailReply(contextSize: size, drawing: { context in
                let bounds = CGRect(origin: .zero, size: size)
                context.saveGState()
                context.setFillColor(NSColor.white.cgColor)
                context.fill(bounds)

                let imageSize = image.size
                guard imageSize.width > 0, imageSize.height > 0 else {
                    context.restoreGState()
                    return false
                }
                let scale = min(size.width / imageSize.width, size.height / imageSize.height)
                let fitted = CGSize(width: imageSize.width * scale, height: imageSize.height * scale)
                let rect = CGRect(
                    x: (size.width - fitted.width) / 2,
                    y: (size.height - fitted.height) / 2,
                    width: fitted.width,
                    height: fitted.height
                )
                NSGraphicsContext.saveGraphicsState()
                NSGraphicsContext.current = NSGraphicsContext(cgContext: context, flipped: false)
                image.draw(in: rect, from: .zero, operation: .copy, fraction: 1.0)
                NSGraphicsContext.restoreGraphicsState()
                context.restoreGState()
                return true
            })
            handler(reply, nil)
        } catch {
            // In particular, don't persist a cached image thumbnail when the
            // signed manifest declares screenshot: deny or fails verification.
            handler(nil, error)
        }
    }
}
