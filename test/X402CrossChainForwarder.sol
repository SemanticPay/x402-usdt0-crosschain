// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import "forge-std/Test.sol";
import "../src/X402CrossChainForwarder.sol";

contract MockEIP3009Token {
    string public constant name = "MockUSDT0";
    string public constant version = "1";
    uint8 public constant decimals = 6;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => mapping(bytes32 => bool)) public authorizationState;

    bytes32 public DOMAIN_SEPARATOR;

    bytes32 constant RECEIVE_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    constructor() {
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(bytes(name)),
            keccak256(bytes(version)),
            block.chainid,
            address(this)
        ));
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "MockToken: insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external {
        require(to == msg.sender, "EIP3009: caller must be the payee");
        require(block.timestamp > validAfter, "EIP3009: authorization is not yet valid");
        require(block.timestamp < validBefore, "EIP3009: authorization is expired");
        require(!authorizationState[from][nonce], "EIP3009: authorization is used");

        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            keccak256(abi.encode(RECEIVE_TYPEHASH, from, to, value, validAfter, validBefore, nonce))
        ));

        require(signature.length == 65, "EIP3009: invalid signature length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        address recovered = ecrecover(digest, v, r, s);
        require(recovered != address(0) && recovered == from, "EIP3009: invalid signature");

        authorizationState[from][nonce] = true;
        balanceOf[from] -= value;
        balanceOf[to] += value;
    }
}

contract MockOFT {
    address public token;
    uint64 public sendCount;

    uint32 public lastDstEid;
    bytes32 public lastTo;
    uint256 public lastAmountLD;
    uint256 public lastMinAmountLD;
    uint256 public lastNativeFee;
    address public lastRefundAddress;
    bytes32 public lastGuid;

    constructor(address _token) {
        token = _token;
    }

    receive() external payable {}

    function send(
        IOFT.SendParam calldata sendParam,
        IOFT.MessagingFee calldata fee,
        address refundAddress
    ) external payable returns (IOFT.MessagingReceipt memory, IOFT.OFTReceipt memory) {
        MockEIP3009Token(token).transferFrom(msg.sender, address(this), sendParam.amountLD);

        sendCount++;
        lastDstEid = sendParam.dstEid;
        lastTo = sendParam.to;
        lastAmountLD = sendParam.amountLD;
        lastMinAmountLD = sendParam.minAmountLD;
        lastNativeFee = fee.nativeFee;
        lastRefundAddress = refundAddress;
        lastGuid = keccak256(abi.encode(sendParam.dstEid, sendParam.to, sendParam.amountLD, sendCount));

        return (
            IOFT.MessagingReceipt({
                guid: lastGuid,
                nonce: sendCount,
                fee: IOFT.MessagingFee({ nativeFee: fee.nativeFee, lzTokenFee: 0 })
            }),
            IOFT.OFTReceipt({
                amountSentLD: sendParam.amountLD,
                amountReceivedLD: sendParam.amountLD
            })
        );
    }
}

contract X402CrossChainForwarderTest is Test {

    uint256 constant BUYER_PRIVATE_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address BUYER;

    bytes32 constant SERVER_BYTES32 = bytes32(uint256(uint160(0xBEEF)));
    bytes32 constant ATTACKER_BYTES32 = bytes32(uint256(uint160(0xDEAD)));
    uint32 constant DST_EID_STABLE = 30396;
    uint32 constant DST_EID_PLASMA = 30383;
    uint256 constant PAYMENT_AMOUNT = 100_000_000;
    uint256 constant BUYER_INITIAL_BALANCE = 1_000_000_000;
    uint256 constant VALID_AFTER = 0;
    uint256 constant VALID_BEFORE = 2_000_000_000;
    uint256 constant MIN_AMOUNT_LD = 100_000_000;
    uint256 constant LZ_FEE = 0.001 ether;
    address constant REFUND_ADDRESS = address(0xCAFE);
    uint256 constant BLOCK_TIMESTAMP = 1_000_000_000;

    bytes32 constant RECEIVE_TYPEHASH = keccak256(
        "ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );

    MockEIP3009Token token;
    MockOFT oft;
    X402CrossChainForwarder forwarder;

    function setUp() public {
        BUYER = vm.addr(BUYER_PRIVATE_KEY);
        vm.warp(BLOCK_TIMESTAMP);

        token = new MockEIP3009Token();
        oft = new MockOFT(address(token));
        forwarder = new X402CrossChainForwarder(address(token), address(oft));

        token.mint(BUYER, BUYER_INITIAL_BALANCE);
    }

    function _signAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter_,
        uint256 validBefore_,
        bytes32 nonce
    ) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            token.DOMAIN_SEPARATOR(),
            keccak256(abi.encode(RECEIVE_TYPEHASH, from, to, value, validAfter_, validBefore_, nonce))
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BUYER_PRIVATE_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signForPayment(
        X402CrossChainForwarder.BridgeParams memory bridge,
        uint256 value,
        uint256 validBefore_
    ) internal view returns (bytes memory) {
        bytes32 nonce = forwarder.computeNonce(bridge.dstEid, bridge.server, bridge.minAmountLD, validBefore_);
        return _signAuthorization(BUYER, address(forwarder), value, VALID_AFTER, validBefore_, nonce);
    }

    function _defaultAuth(bytes memory signature) internal view returns (X402CrossChainForwarder.PaymentAuthorization memory) {
        return X402CrossChainForwarder.PaymentAuthorization({
            from: BUYER,
            value: PAYMENT_AMOUNT,
            validAfter: VALID_AFTER,
            validBefore: VALID_BEFORE,
            signature: signature
        });
    }

    function _defaultBridge() internal pure returns (X402CrossChainForwarder.BridgeParams memory) {
        return X402CrossChainForwarder.BridgeParams({
            dstEid: DST_EID_STABLE,
            server: SERVER_BYTES32,
            minAmountLD: MIN_AMOUNT_LD,
            extraOptions: "",
            refundAddress: REFUND_ADDRESS
        });
    }

    function test_constructor_shouldSetTokenToProvidedAddress() public view {
        assertEq(address(forwarder.TOKEN()), address(token));
    }

    function test_constructor_shouldSetOFTToProvidedAddress() public view {
        assertEq(address(forwarder.OFT()), address(oft));
    }

    function test_constructor_shouldApproveOFTForMaxTokenSpend() public view {
        uint256 approved = token.allowance(address(forwarder), address(oft));

        assertEq(approved, type(uint256).max);
    }

    function test_computeNonce_shouldMatchKeccak256OfAbiEncodedParams() public view {
        bytes32 expected = keccak256(abi.encode(DST_EID_STABLE, SERVER_BYTES32, MIN_AMOUNT_LD, VALID_BEFORE));

        bytes32 actual = forwarder.computeNonce(DST_EID_STABLE, SERVER_BYTES32, MIN_AMOUNT_LD, VALID_BEFORE);

        assertEq(actual, expected);
    }

    function test_computeNonce_shouldBeDeterministic() public view {
        bytes32 first = forwarder.computeNonce(DST_EID_STABLE, SERVER_BYTES32, MIN_AMOUNT_LD, VALID_BEFORE);

        bytes32 second = forwarder.computeNonce(DST_EID_STABLE, SERVER_BYTES32, MIN_AMOUNT_LD, VALID_BEFORE);

        assertEq(first, second);
    }

    function test_computeNonce_shouldChangeWhenDstEidDiffers() public view {
        bytes32 nonceA = forwarder.computeNonce(DST_EID_STABLE, SERVER_BYTES32, MIN_AMOUNT_LD, VALID_BEFORE);

        bytes32 nonceB = forwarder.computeNonce(DST_EID_PLASMA, SERVER_BYTES32, MIN_AMOUNT_LD, VALID_BEFORE);

        assertTrue(nonceA != nonceB);
    }

    function test_computeNonce_shouldChangeWhenSellerDiffers() public view {
        bytes32 nonceA = forwarder.computeNonce(DST_EID_STABLE, SERVER_BYTES32, MIN_AMOUNT_LD, VALID_BEFORE);

        bytes32 nonceB = forwarder.computeNonce(DST_EID_STABLE, ATTACKER_BYTES32, MIN_AMOUNT_LD, VALID_BEFORE);

        assertTrue(nonceA != nonceB);
    }

    function test_computeNonce_shouldChangeWhenMinAmountDiffers() public view {
        bytes32 nonceA = forwarder.computeNonce(DST_EID_STABLE, SERVER_BYTES32, MIN_AMOUNT_LD, VALID_BEFORE);

        bytes32 nonceB = forwarder.computeNonce(DST_EID_STABLE, SERVER_BYTES32, 50_000_000, VALID_BEFORE);

        assertTrue(nonceA != nonceB);
    }

    function test_computeNonce_shouldChangeWhenValidBeforeDiffers() public view {
        bytes32 nonceA = forwarder.computeNonce(DST_EID_STABLE, SERVER_BYTES32, MIN_AMOUNT_LD, VALID_BEFORE);

        bytes32 nonceB = forwarder.computeNonce(DST_EID_STABLE, SERVER_BYTES32, MIN_AMOUNT_LD, VALID_BEFORE + 1);

        assertTrue(nonceA != nonceB);
    }

    function test_forwardPayment_shouldRevertWhenValueIsZero() public {
        X402CrossChainForwarder.BridgeParams memory bridge = _defaultBridge();
        bytes memory signature = _signForPayment(bridge, PAYMENT_AMOUNT, VALID_BEFORE);
        X402CrossChainForwarder.PaymentAuthorization memory auth = _defaultAuth(signature);
        auth.value = 0;

        vm.expectRevert(X402CrossChainForwarder.ZeroAmount.selector);
        forwarder.forwardPayment{value: LZ_FEE}(auth, bridge);
    }

    function test_forwardPayment_shouldRevertWhenServerIsZeroBytes32() public {
        X402CrossChainForwarder.BridgeParams memory bridge = _defaultBridge();
        bridge.server = bytes32(0);
        bytes memory signature = _signForPayment(bridge, PAYMENT_AMOUNT, VALID_BEFORE);
        X402CrossChainForwarder.PaymentAuthorization memory auth = _defaultAuth(signature);

        vm.expectRevert(X402CrossChainForwarder.InvalidRecipient.selector);
        forwarder.forwardPayment{value: LZ_FEE}(auth, bridge);
    }

    function test_forwardPayment_shouldDebitBuyerByPaymentAmount() public {
        X402CrossChainForwarder.BridgeParams memory bridge = _defaultBridge();
        bytes memory signature = _signForPayment(bridge, PAYMENT_AMOUNT, VALID_BEFORE);
        X402CrossChainForwarder.PaymentAuthorization memory auth = _defaultAuth(signature);

        forwarder.forwardPayment{value: LZ_FEE}(auth, bridge);

        assertEq(token.balanceOf(BUYER), BUYER_INITIAL_BALANCE - PAYMENT_AMOUNT);
    }

    function test_forwardPayment_shouldLeaveZeroTokensOnForwarder() public {
        X402CrossChainForwarder.BridgeParams memory bridge = _defaultBridge();
        bytes memory signature = _signForPayment(bridge, PAYMENT_AMOUNT, VALID_BEFORE);
        X402CrossChainForwarder.PaymentAuthorization memory auth = _defaultAuth(signature);

        forwarder.forwardPayment{value: LZ_FEE}(auth, bridge);

        assertEq(token.balanceOf(address(forwarder)), 0);
    }

    function test_forwardPayment_shouldTransferTokensToOFTForBurning() public {
        X402CrossChainForwarder.BridgeParams memory bridge = _defaultBridge();
        bytes memory signature = _signForPayment(bridge, PAYMENT_AMOUNT, VALID_BEFORE);
        X402CrossChainForwarder.PaymentAuthorization memory auth = _defaultAuth(signature);

        forwarder.forwardPayment{value: LZ_FEE}(auth, bridge);

        assertEq(token.balanceOf(address(oft)), PAYMENT_AMOUNT);
    }

    function test_forwardPayment_shouldCallOFTSendWithCorrectBridgeParams() public {
        X402CrossChainForwarder.BridgeParams memory bridge = _defaultBridge();
        bytes memory signature = _signForPayment(bridge, PAYMENT_AMOUNT, VALID_BEFORE);
        X402CrossChainForwarder.PaymentAuthorization memory auth = _defaultAuth(signature);

        forwarder.forwardPayment{value: LZ_FEE}(auth, bridge);

        assertEq(oft.lastDstEid(), DST_EID_STABLE);
        assertEq(oft.lastTo(), SERVER_BYTES32);
        assertEq(oft.lastAmountLD(), PAYMENT_AMOUNT);
        assertEq(oft.lastMinAmountLD(), MIN_AMOUNT_LD);
        assertEq(oft.lastRefundAddress(), REFUND_ADDRESS);
    }

    function test_forwardPayment_shouldPassMsgValueAsNativeFeeToOFT() public {
        X402CrossChainForwarder.BridgeParams memory bridge = _defaultBridge();
        bytes memory signature = _signForPayment(bridge, PAYMENT_AMOUNT, VALID_BEFORE);
        X402CrossChainForwarder.PaymentAuthorization memory auth = _defaultAuth(signature);
        uint256 specificFee = 0.005 ether;

        forwarder.forwardPayment{value: specificFee}(auth, bridge);

        assertEq(oft.lastNativeFee(), specificFee);
        assertEq(address(oft).balance, specificFee);
    }

    function test_forwardPayment_shouldEmitCrossChainPaymentEvent() public {
        X402CrossChainForwarder.BridgeParams memory bridge = _defaultBridge();
        bytes memory signature = _signForPayment(bridge, PAYMENT_AMOUNT, VALID_BEFORE);
        X402CrossChainForwarder.PaymentAuthorization memory auth = _defaultAuth(signature);
        bytes32 expectedGuid = keccak256(abi.encode(DST_EID_STABLE, SERVER_BYTES32, uint256(PAYMENT_AMOUNT), uint64(1)));

        vm.expectEmit(true, true, false, true);
        emit X402CrossChainForwarder.CrossChainPayment(BUYER, SERVER_BYTES32, DST_EID_STABLE, PAYMENT_AMOUNT, expectedGuid);

        forwarder.forwardPayment{value: LZ_FEE}(auth, bridge);
    }

    function test_forwardPayment_shouldRevertWhenDstEidIsTampered() public {
        X402CrossChainForwarder.BridgeParams memory bridge = _defaultBridge();
        bytes memory signature = _signForPayment(bridge, PAYMENT_AMOUNT, VALID_BEFORE);
        X402CrossChainForwarder.PaymentAuthorization memory auth = _defaultAuth(signature);
        bridge.dstEid = DST_EID_PLASMA;

        vm.expectRevert("EIP3009: invalid signature");
        forwarder.forwardPayment{value: LZ_FEE}(auth, bridge);
    }

    function test_forwardPayment_shouldRevertWhenServerIsTampered() public {
        X402CrossChainForwarder.BridgeParams memory bridge = _defaultBridge();
        bytes memory signature = _signForPayment(bridge, PAYMENT_AMOUNT, VALID_BEFORE);
        X402CrossChainForwarder.PaymentAuthorization memory auth = _defaultAuth(signature);
        bridge.server = ATTACKER_BYTES32;

        vm.expectRevert("EIP3009: invalid signature");
        forwarder.forwardPayment{value: LZ_FEE}(auth, bridge);
    }

    function test_forwardPayment_shouldRevertWhenMinAmountIsTampered() public {
        X402CrossChainForwarder.BridgeParams memory bridge = _defaultBridge();
        bytes memory signature = _signForPayment(bridge, PAYMENT_AMOUNT, VALID_BEFORE);
        X402CrossChainForwarder.PaymentAuthorization memory auth = _defaultAuth(signature);
        bridge.minAmountLD = 50_000_000;

        vm.expectRevert("EIP3009: invalid signature");
        forwarder.forwardPayment{value: LZ_FEE}(auth, bridge);
    }

    function test_forwardPayment_shouldRevertWhenSignatureIsReplayed() public {
        X402CrossChainForwarder.BridgeParams memory bridge = _defaultBridge();
        bytes memory signature = _signForPayment(bridge, PAYMENT_AMOUNT, VALID_BEFORE);
        X402CrossChainForwarder.PaymentAuthorization memory auth = _defaultAuth(signature);
        forwarder.forwardPayment{value: LZ_FEE}(auth, bridge);

        vm.expectRevert("EIP3009: authorization is used");
        forwarder.forwardPayment{value: LZ_FEE}(auth, bridge);
    }

    function test_forwardPayment_shouldRevertWhenAuthorizationIsExpired() public {
        X402CrossChainForwarder.BridgeParams memory bridge = _defaultBridge();
        bytes memory signature = _signForPayment(bridge, PAYMENT_AMOUNT, VALID_BEFORE);
        X402CrossChainForwarder.PaymentAuthorization memory auth = _defaultAuth(signature);

        vm.warp(VALID_BEFORE + 1);

        vm.expectRevert("EIP3009: authorization is expired");
        forwarder.forwardPayment{value: LZ_FEE}(auth, bridge);
    }

    function test_forwardPayment_shouldRevertWhenBuyerHasInsufficientBalance() public {
        uint256 excessiveAmount = BUYER_INITIAL_BALANCE + 1;
        X402CrossChainForwarder.BridgeParams memory bridge = _defaultBridge();
        bytes32 nonce = forwarder.computeNonce(bridge.dstEid, bridge.server, bridge.minAmountLD, VALID_BEFORE);
        bytes memory signature = _signAuthorization(
            BUYER, address(forwarder), excessiveAmount, VALID_AFTER, VALID_BEFORE, nonce
        );
        X402CrossChainForwarder.PaymentAuthorization memory auth = _defaultAuth(signature);
        auth.value = excessiveAmount;

        vm.expectRevert();
        forwarder.forwardPayment{value: LZ_FEE}(auth, bridge);
    }
}