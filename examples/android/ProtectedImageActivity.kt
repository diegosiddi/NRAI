package example.nrai

import android.app.Activity
import android.graphics.Bitmap
import android.os.Bundle
import android.view.WindowManager
import android.widget.ImageView

/**
 * Integration sketch. The host must parse NRAI, verify the signature and payload,
 * and obtain the decoded bitmap before calling showVerifiedImage. Do not trust a
 * screenshot field from an unverified manifest.
 */
class ProtectedImageActivity : Activity() {
    fun showVerifiedImage(bitmap: Bitmap, screenshotRight: String) {
        if (screenshotRight == "deny") {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
        setContentView(ImageView(this).apply {
            setImageBitmap(bitmap)
            adjustViewBounds = true
        })
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Connect a verified NRAI document through your file picker / application flow.
    }

    override fun onDestroy() {
        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        super.onDestroy()
    }
}
