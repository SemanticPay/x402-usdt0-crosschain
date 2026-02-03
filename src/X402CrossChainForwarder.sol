// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

interface IEIP3009 {
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external;
}

interface IOFT {
    struct SendParam {
        uint32 dstEid;
        bytes32 to;
        uint256 amountLD;
        uint256 minAmountLD;
        bytes extraOptions;
        bytes composeMsg;
        bytes oftCmd;
    }

    struct MessagingFee {
        uint256 nativeFee;
        uint256 lzTokenFee;
    }

    struct MessagingReceipt {
        bytes32 guid;
        uint64 nonce;
        MessagingFee fee;
    }

    struct OFTReceipt {
        uint256 amountSentLD;
        uint256 amountReceivedLD;
    }

    function send(
        SendParam calldata sendParam,
        MessagingFee calldata fee,
        address refundAddress
    ) external payable returns (MessagingReceipt memory, OFTReceipt memory);
}

contract X402CrossChainForwarder {

    struct PaymentAuthorization {
        address from;
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes signature;
    }

    struct BridgeParams {
        uint32 dstEid;
        bytes32 server;
        uint256 minAmountLD;
        bytes extraOptions;
        address refundAddress;
    }

    IEIP3009 public immutable TOKEN;
    IOFT    public immutable OFT;

    error ZeroAmount();
    error InvalidRecipient();

    event CrossChainPayment(
        address indexed client,
        bytes32 indexed server,
        uint32  dstEid,
        uint256 amount,
        bytes32 guid
    );

    constructor(address _token, address _oft) {
        TOKEN = IEIP3009(_token);
        OFT   = IOFT(_oft);
        IERC20(_token).approve(_oft, type(uint256).max);
    }

    function computeNonce(
        uint32 dstEid,
        bytes32 server,
        uint256 minAmountLD,
        uint256 validBefore
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(dstEid, server, minAmountLD, validBefore));
    }

    function forwardPayment(
        PaymentAuthorization calldata auth,
        BridgeParams calldata bridge
    ) external payable {
        if (auth.value == 0) revert ZeroAmount();
        if (bridge.server == bytes32(0)) revert InvalidRecipient();

        bytes32 nonce = computeNonce(
            bridge.dstEid, bridge.server, bridge.minAmountLD, auth.validBefore
        );

        TOKEN.receiveWithAuthorization(
            auth.from,
            address(this),
            auth.value,
            auth.validAfter,
            auth.validBefore,
            nonce,
            auth.signature
        );

        (IOFT.MessagingReceipt memory receipt, ) = OFT.send{value: msg.value}(
            IOFT.SendParam({
                dstEid:       bridge.dstEid,
                to:           bridge.server,
                amountLD:     auth.value,
                minAmountLD:  bridge.minAmountLD,
                extraOptions: bridge.extraOptions,
                composeMsg:   "",
                oftCmd:       ""
            }),
            IOFT.MessagingFee({
                nativeFee:  msg.value,
                lzTokenFee: 0
            }),
            bridge.refundAddress
        );

        emit CrossChainPayment(
            auth.from, bridge.server, bridge.dstEid, auth.value, receipt.guid
        );
    }
}