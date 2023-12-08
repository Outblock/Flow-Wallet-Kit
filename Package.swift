// swift-tools-version: 5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "FlowWalletCore",
    platforms: [
            .macOS(.v10_14), .iOS(.v13), .tvOS(.v13)
    ],
    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "FlowWalletCore",
            targets: ["FlowWalletCore"]),
    ],
    dependencies: [
        .package(url: "https://github.com/kishikawakatsumi/KeychainAccess", from: "4.2.2"),
        .package(url: "https://github.com/outblock/flow-swift.git", from: "0.3.2")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.

        .target(
            name: "FlowWalletCore",
            dependencies: ["KeychainAccess", .product(name: "Flow",package: "flow-swift")],
            path: "iOS/FlowWalletCore/Sources"
        ),
        .testTarget(
            name: "FlowWalletCoreTests",
            dependencies: ["FlowWalletCore"],
            path: "iOS/FlowWalletCore/Tests"
        )
    ]
)
