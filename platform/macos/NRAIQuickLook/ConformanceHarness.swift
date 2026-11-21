import Foundation

@main
struct ConformanceHarness {
    static func main() throws {
        let vectorDirectory = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
        let catalogURL = vectorDirectory.appendingPathComponent("catalog.json")
        let catalogData = try Data(contentsOf: catalogURL)
        let catalog = try JSONSerialization.jsonObject(with: catalogData) as! [String: Any]
        let vectors = catalog["vectors"] as! [[String: Any]]

        for vector in vectors {
            let file = vector["file"] as! String
            let expected = vector["expected"] as! String
            let url = vectorDirectory.appendingPathComponent(file)
            let data = try Data(contentsOf: url)
            do {
                _ = try NRAIV1.verifiedPayload(from: data)
                guard expected == "accept" else { fatalError("Swift verifier unexpectedly accepted \(file)") }
            } catch {
                guard expected == "reject" else { fatalError("Swift verifier rejected \(file): \(error)") }
            }
        }
        print("Swift verifier accepted and rejected all NRAI v1 conformance vectors.")
    }
}
