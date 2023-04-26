RELEASE = False
if RELEASE:
    import idaapi
    import idautils
    import idaapi
    import idc
else:
    import sys

    sys.path.append("./ida_lib")
    from ida_lib import *

print("new ------------------------------------------")


# ea = idc.get_curline()
# print(ea)

def GetOperandTypeName(t):
    if t == -1:
        return "error                        "
    elif t == 0:
        return "o_void   : No Operand        "
    elif t == 1:
        return "o_reg    : reg               "
    elif t == 2:
        return "o_mem    : addr              "
    elif t == 3:
        return "o_phrase : phrase            "
    elif t == 4:
        return "o_displ  : phrase + addr     "
    elif t == 5:
        return "o_imm    : value             "
    elif t == 6:
        return "o_far    : far addr          "
    elif t == 7:
        return "o_near   : near addr         "
    elif t == 8:
        return "o_trreg  : trace reg         "
    return str(t)


#
def GetWdfVersionBindObject(addr):
    for x in XrefsTo(addr, flags=0):
        cur_addr = x.frm
        cur_asm = GetDisasm(cur_addr)
        if cur_asm.startswith("call"):
            pass
        else:
            continue

        func_addr = idc.get_func_attr(cur_addr, FUNCATTR_START)

        pre_addr = cur_addr
        while True:
            if pre_addr <= func_addr:
                break
            pre_addr = idc.prev_head(pre_addr)
            pre_asm = GetDisasm(pre_addr)
            if pre_asm.startswith("lea"):
                t = idc.get_operand_type(pre_addr, 0)
                # 寄存器
                if t != 1:
                    break

                data = idc.get_operand_value(pre_addr, 0)
                # r8
                if data == 8:
                    t = idc.get_operand_type(pre_addr, 1)
                    data = idc.get_operand_value(pre_addr, 1)
                    return data
    return 0


def GetNameByID_01031(id):
    switcher = {
        0: 'WdfChildListCreate',
        1: 'WdfChildListGetDevice',
        2: 'WdfChildListRetrievePdo',
        3: 'WdfChildListRetrieveAddressDescription',
        4: 'WdfChildListBeginScan',
        5: 'WdfChildListEndScan',
        6: 'WdfChildListBeginIteration',
        7: 'WdfChildListRetrieveNextDevice',
        8: 'WdfChildListEndIteration',
        9: 'WdfChildListAddOrUpdateChildDescriptionAsPresent',
        10: 'WdfChildListUpdateChildDescriptionAsMissing',
        11: 'WdfChildListUpdateAllChildDescriptionsAsPresent',
        12: 'WdfChildListRequestChildEject',
        13: 'WdfCollectionCreate',
        14: 'WdfCollectionGetCount',
        15: 'WdfCollectionAdd',
        16: 'WdfCollectionRemove',
        17: 'WdfCollectionRemoveItem',
        18: 'WdfCollectionGetItem',
        19: 'WdfCollectionGetFirstItem',
        20: 'WdfCollectionGetLastItem',
        21: 'WdfCommonBufferCreate',
        22: 'WdfCommonBufferGetAlignedVirtualAddress',
        23: 'WdfCommonBufferGetAlignedLogicalAddress',
        24: 'WdfCommonBufferGetLength',
        25: 'WdfControlDeviceInitAllocate',
        26: 'WdfControlDeviceInitSetShutdownNotification',
        27: 'WdfControlFinishInitializing',
        28: 'WdfDeviceGetDeviceState',
        29: 'WdfDeviceSetDeviceState',
        30: 'WdfWdmDeviceGetWdfDeviceHandle',
        31: 'WdfDeviceWdmGetDeviceObject',
        32: 'WdfDeviceWdmGetAttachedDevice',
        33: 'WdfDeviceWdmGetPhysicalDevice',
        34: 'WdfDeviceWdmDispatchPreprocessedIrp',
        35: 'WdfDeviceAddDependentUsageDeviceObject',
        36: 'WdfDeviceAddRemovalRelationsPhysicalDevice',
        37: 'WdfDeviceRemoveRemovalRelationsPhysicalDevice',
        38: 'WdfDeviceClearRemovalRelationsDevices',
        39: 'WdfDeviceGetDriver',
        40: 'WdfDeviceRetrieveDeviceName',
        41: 'WdfDeviceAssignMofResourceName',
        42: 'WdfDeviceGetIoTarget',
        43: 'WdfDeviceGetDevicePnpState',
        44: 'WdfDeviceGetDevicePowerState',
        45: 'WdfDeviceGetDevicePowerPolicyState',
        46: 'WdfDeviceAssignS0IdleSettings',
        47: 'WdfDeviceAssignSxWakeSettings',
        48: 'WdfDeviceOpenRegistryKey',
        49: 'WdfDeviceSetSpecialFileSupport',
        50: 'WdfDeviceSetCharacteristics',
        51: 'WdfDeviceGetCharacteristics',
        52: 'WdfDeviceGetAlignmentRequirement',
        53: 'WdfDeviceSetAlignmentRequirement',
        54: 'WdfDeviceInitFree',
        55: 'WdfDeviceInitSetPnpPowerEventCallbacks',
        56: 'WdfDeviceInitSetPowerPolicyEventCallbacks',
        57: 'WdfDeviceInitSetPowerPolicyOwnership',
        58: 'WdfDeviceInitRegisterPnpStateChangeCallback',
        59: 'WdfDeviceInitRegisterPowerStateChangeCallback',
        60: 'WdfDeviceInitRegisterPowerPolicyStateChangeCallback',
        61: 'WdfDeviceInitSetIoType',
        62: 'WdfDeviceInitSetExclusive',
        63: 'WdfDeviceInitSetPowerNotPageable',
        64: 'WdfDeviceInitSetPowerPageable',
        65: 'WdfDeviceInitSetPowerInrush',
        66: 'WdfDeviceInitSetDeviceType',
        67: 'WdfDeviceInitAssignName',
        68: 'WdfDeviceInitAssignSDDLString',
        69: 'WdfDeviceInitSetDeviceClass',
        70: 'WdfDeviceInitSetCharacteristics',
        71: 'WdfDeviceInitSetFileObjectConfig',
        72: 'WdfDeviceInitSetRequestAttributes',
        73: 'WdfDeviceInitAssignWdmIrpPreprocessCallback',
        74: 'WdfDeviceInitSetIoInCallerContextCallback',
        75: 'WdfDeviceCreate',
        76: 'WdfDeviceSetStaticStopRemove',
        77: 'WdfDeviceCreateDeviceInterface',
        78: 'WdfDeviceSetDeviceInterfaceState',
        79: 'WdfDeviceRetrieveDeviceInterfaceString',
        80: 'WdfDeviceCreateSymbolicLink',
        81: 'WdfDeviceQueryProperty',
        82: 'WdfDeviceAllocAndQueryProperty',
        83: 'WdfDeviceSetPnpCapabilities',
        84: 'WdfDeviceSetPowerCapabilities',
        85: 'WdfDeviceSetBusInformationForChildren',
        86: 'WdfDeviceIndicateWakeStatus',
        87: 'WdfDeviceSetFailed',
        88: 'WdfDeviceStopIdleNoTrack',
        89: 'WdfDeviceResumeIdleNoTrack',
        90: 'WdfDeviceGetFileObject',
        91: 'WdfDeviceEnqueueRequest',
        92: 'WdfDeviceGetDefaultQueue',
        93: 'WdfDeviceConfigureRequestDispatching',
        94: 'WdfDmaEnablerCreate',
        95: 'WdfDmaEnablerGetMaximumLength',
        96: 'WdfDmaEnablerGetMaximumScatterGatherElements',
        97: 'WdfDmaEnablerSetMaximumScatterGatherElements',
        98: 'WdfDmaTransactionCreate',
        99: 'WdfDmaTransactionInitialize',
        100: 'WdfDmaTransactionInitializeUsingRequest',
        101: 'WdfDmaTransactionExecute',
        102: 'WdfDmaTransactionRelease',
        103: 'WdfDmaTransactionDmaCompleted',
        104: 'WdfDmaTransactionDmaCompletedWithLength',
        105: 'WdfDmaTransactionDmaCompletedFinal',
        106: 'WdfDmaTransactionGetBytesTransferred',
        107: 'WdfDmaTransactionSetMaximumLength',
        108: 'WdfDmaTransactionGetRequest',
        109: 'WdfDmaTransactionGetCurrentDmaTransferLength',
        110: 'WdfDmaTransactionGetDevice',
        111: 'WdfDpcCreate',
        112: 'WdfDpcEnqueue',
        113: 'WdfDpcCancel',
        114: 'WdfDpcGetParentObject',
        115: 'WdfDpcWdmGetDpc',
        116: 'WdfDriverCreate',
        117: 'WdfDriverGetRegistryPath',
        118: 'WdfDriverWdmGetDriverObject',
        119: 'WdfDriverOpenParametersRegistryKey',
        120: 'WdfWdmDriverGetWdfDriverHandle',
        121: 'WdfDriverRegisterTraceInfo',
        122: 'WdfDriverRetrieveVersionString',
        123: 'WdfDriverIsVersionAvailable',
        124: 'WdfFdoInitWdmGetPhysicalDevice',
        125: 'WdfFdoInitOpenRegistryKey',
        126: 'WdfFdoInitQueryProperty',
        127: 'WdfFdoInitAllocAndQueryProperty',
        128: 'WdfFdoInitSetEventCallbacks',
        129: 'WdfFdoInitSetFilter',
        130: 'WdfFdoInitSetDefaultChildListConfig',
        131: 'WdfFdoQueryForInterface',
        132: 'WdfFdoGetDefaultChildList',
        133: 'WdfFdoAddStaticChild',
        134: 'WdfFdoLockStaticChildListForIteration',
        135: 'WdfFdoRetrieveNextStaticChild',
        136: 'WdfFdoUnlockStaticChildListFromIteration',
        137: 'WdfFileObjectGetFileName',
        138: 'WdfFileObjectGetFlags',
        139: 'WdfFileObjectGetDevice',
        140: 'WdfFileObjectWdmGetFileObject',
        141: 'WdfInterruptCreate',
        142: 'WdfInterruptQueueDpcForIsr',
        143: 'WdfInterruptSynchronize',
        144: 'WdfInterruptAcquireLock',
        145: 'WdfInterruptReleaseLock',
        146: 'WdfInterruptEnable',
        147: 'WdfInterruptDisable',
        148: 'WdfInterruptWdmGetInterrupt',
        149: 'WdfInterruptGetInfo',
        150: 'WdfInterruptSetPolicy',
        151: 'WdfInterruptGetDevice',
        152: 'WdfIoQueueCreate',
        153: 'WdfIoQueueGetState',
        154: 'WdfIoQueueStart',
        155: 'WdfIoQueueStop',
        156: 'WdfIoQueueStopSynchronously',
        157: 'WdfIoQueueGetDevice',
        158: 'WdfIoQueueRetrieveNextRequest',
        159: 'WdfIoQueueRetrieveRequestByFileObject',
        160: 'WdfIoQueueFindRequest',
        161: 'WdfIoQueueRetrieveFoundRequest',
        162: 'WdfIoQueueDrainSynchronously',
        163: 'WdfIoQueueDrain',
        164: 'WdfIoQueuePurgeSynchronously',
        165: 'WdfIoQueuePurge',
        166: 'WdfIoQueueReadyNotify',
        167: 'WdfIoTargetCreate',
        168: 'WdfIoTargetOpen',
        169: 'WdfIoTargetCloseForQueryRemove',
        170: 'WdfIoTargetClose',
        171: 'WdfIoTargetStart',
        172: 'WdfIoTargetStop',
        173: 'WdfIoTargetGetState',
        174: 'WdfIoTargetGetDevice',
        175: 'WdfIoTargetQueryTargetProperty',
        176: 'WdfIoTargetAllocAndQueryTargetProperty',
        177: 'WdfIoTargetQueryForInterface',
        178: 'WdfIoTargetWdmGetTargetDeviceObject',
        179: 'WdfIoTargetWdmGetTargetPhysicalDevice',
        180: 'WdfIoTargetWdmGetTargetFileObject',
        181: 'WdfIoTargetWdmGetTargetFileHandle',
        182: 'WdfIoTargetSendReadSynchronously',
        183: 'WdfIoTargetFormatRequestForRead',
        184: 'WdfIoTargetSendWriteSynchronously',
        185: 'WdfIoTargetFormatRequestForWrite',
        186: 'WdfIoTargetSendIoctlSynchronously',
        187: 'WdfIoTargetFormatRequestForIoctl',
        188: 'WdfIoTargetSendInternalIoctlSynchronously',
        189: 'WdfIoTargetFormatRequestForInternalIoctl',
        190: 'WdfIoTargetSendInternalIoctlOthersSynchronously',
        191: 'WdfIoTargetFormatRequestForInternalIoctlOthers',
        192: 'WdfMemoryCreate',
        193: 'WdfMemoryCreatePreallocated',
        194: 'WdfMemoryGetBuffer',
        195: 'WdfMemoryAssignBuffer',
        196: 'WdfMemoryCopyToBuffer',
        197: 'WdfMemoryCopyFromBuffer',
        198: 'WdfLookasideListCreate',
        199: 'WdfMemoryCreateFromLookaside',
        200: 'WdfDeviceMiniportCreate',
        201: 'WdfDriverMiniportUnload',
        202: 'WdfObjectGetTypedContextWorker',
        203: 'WdfObjectAllocateContext',
        204: 'WdfObjectContextGetObject',
        205: 'WdfObjectReferenceActual',
        206: 'WdfObjectDereferenceActual',
        207: 'WdfObjectCreate',
        208: 'WdfObjectDelete',
        209: 'WdfObjectQuery',
        210: 'WdfPdoInitAllocate',
        211: 'WdfPdoInitSetEventCallbacks',
        212: 'WdfPdoInitAssignDeviceID',
        213: 'WdfPdoInitAssignInstanceID',
        214: 'WdfPdoInitAddHardwareID',
        215: 'WdfPdoInitAddCompatibleID',
        216: 'WdfPdoInitAddDeviceText',
        217: 'WdfPdoInitSetDefaultLocale',
        218: 'WdfPdoInitAssignRawDevice',
        219: 'WdfPdoMarkMissing',
        220: 'WdfPdoRequestEject',
        221: 'WdfPdoGetParent',
        222: 'WdfPdoRetrieveIdentificationDescription',
        223: 'WdfPdoRetrieveAddressDescription',
        224: 'WdfPdoUpdateAddressDescription',
        225: 'WdfPdoAddEjectionRelationsPhysicalDevice',
        226: 'WdfPdoRemoveEjectionRelationsPhysicalDevice',
        227: 'WdfPdoClearEjectionRelationsDevices',
        228: 'WdfDeviceAddQueryInterface',
        229: 'WdfRegistryOpenKey',
        230: 'WdfRegistryCreateKey',
        231: 'WdfRegistryClose',
        232: 'WdfRegistryWdmGetHandle',
        233: 'WdfRegistryRemoveKey',
        234: 'WdfRegistryRemoveValue',
        235: 'WdfRegistryQueryValue',
        236: 'WdfRegistryQueryMemory',
        237: 'WdfRegistryQueryMultiString',
        238: 'WdfRegistryQueryUnicodeString',
        239: 'WdfRegistryQueryString',
        240: 'WdfRegistryQueryULong',
        241: 'WdfRegistryAssignValue',
        242: 'WdfRegistryAssignMemory',
        243: 'WdfRegistryAssignMultiString',
        244: 'WdfRegistryAssignUnicodeString',
        245: 'WdfRegistryAssignString',
        246: 'WdfRegistryAssignULong',
        247: 'WdfRequestCreate',
        248: 'WdfRequestCreateFromIrp',
        249: 'WdfRequestReuse',
        250: 'WdfRequestChangeTarget',
        251: 'WdfRequestFormatRequestUsingCurrentType',
        252: 'WdfRequestWdmFormatUsingStackLocation',
        253: 'WdfRequestSend',
        254: 'WdfRequestGetStatus',
        255: 'WdfRequestMarkCancelable',
        256: 'WdfRequestUnmarkCancelable',
        257: 'WdfRequestIsCanceled',
        258: 'WdfRequestCancelSentRequest',
        259: 'WdfRequestIsFrom32BitProcess',
        260: 'WdfRequestSetCompletionRoutine',
        261: 'WdfRequestGetCompletionParams',
        262: 'WdfRequestAllocateTimer',
        263: 'WdfRequestComplete',
        264: 'WdfRequestCompleteWithPriorityBoost',
        265: 'WdfRequestCompleteWithInformation',
        266: 'WdfRequestGetParameters',
        267: 'WdfRequestRetrieveInputMemory',
        268: 'WdfRequestRetrieveOutputMemory',
        269: 'WdfRequestRetrieveInputBuffer',
        270: 'WdfRequestRetrieveOutputBuffer',
        271: 'WdfRequestRetrieveInputWdmMdl',
        272: 'WdfRequestRetrieveOutputWdmMdl',
        273: 'WdfRequestRetrieveUnsafeUserInputBuffer',
        274: 'WdfRequestRetrieveUnsafeUserOutputBuffer',
        275: 'WdfRequestSetInformation',
        276: 'WdfRequestGetInformation',
        277: 'WdfRequestGetFileObject',
        278: 'WdfRequestProbeAndLockUserBufferForRead',
        279: 'WdfRequestProbeAndLockUserBufferForWrite',
        280: 'WdfRequestGetRequestorMode',
        281: 'WdfRequestForwardToIoQueue',
        282: 'WdfRequestGetIoQueue',
        283: 'WdfRequestRequeue',
        284: 'WdfRequestStopAcknowledge',
        285: 'WdfRequestWdmGetIrp',
        286: 'WdfIoResourceRequirementsListSetSlotNumber',
        287: 'WdfIoResourceRequirementsListSetInterfaceType',
        288: 'WdfIoResourceRequirementsListAppendIoResList',
        289: 'WdfIoResourceRequirementsListInsertIoResList',
        290: 'WdfIoResourceRequirementsListGetCount',
        291: 'WdfIoResourceRequirementsListGetIoResList',
        292: 'WdfIoResourceRequirementsListRemove',
        293: 'WdfIoResourceRequirementsListRemoveByIoResList',
        294: 'WdfIoResourceListCreate',
        295: 'WdfIoResourceListAppendDescriptor',
        296: 'WdfIoResourceListInsertDescriptor',
        297: 'WdfIoResourceListUpdateDescriptor',
        298: 'WdfIoResourceListGetCount',
        299: 'WdfIoResourceListGetDescriptor',
        300: 'WdfIoResourceListRemove',
        301: 'WdfIoResourceListRemoveByDescriptor',
        302: 'WdfCmResourceListAppendDescriptor',
        303: 'WdfCmResourceListInsertDescriptor',
        304: 'WdfCmResourceListGetCount',
        305: 'WdfCmResourceListGetDescriptor',
        306: 'WdfCmResourceListRemove',
        307: 'WdfCmResourceListRemoveByDescriptor',
        308: 'WdfStringCreate',
        309: 'WdfStringGetUnicodeString',
        310: 'WdfObjectAcquireLock',
        311: 'WdfObjectReleaseLock',
        312: 'WdfWaitLockCreate',
        313: 'WdfWaitLockAcquire',
        314: 'WdfWaitLockRelease',
        315: 'WdfSpinLockCreate',
        316: 'WdfSpinLockAcquire',
        317: 'WdfSpinLockRelease',
        318: 'WdfTimerCreate',
        319: 'WdfTimerStart',
        320: 'WdfTimerStop',
        321: 'WdfTimerGetParentObject',
        322: 'WdfUsbTargetDeviceCreate',
        323: 'WdfUsbTargetDeviceRetrieveInformation',
        324: 'WdfUsbTargetDeviceGetDeviceDescriptor',
        325: 'WdfUsbTargetDeviceRetrieveConfigDescriptor',
        326: 'WdfUsbTargetDeviceQueryString',
        327: 'WdfUsbTargetDeviceAllocAndQueryString',
        328: 'WdfUsbTargetDeviceFormatRequestForString',
        329: 'WdfUsbTargetDeviceGetNumInterfaces',
        330: 'WdfUsbTargetDeviceSelectConfig',
        331: 'WdfUsbTargetDeviceWdmGetConfigurationHandle',
        332: 'WdfUsbTargetDeviceRetrieveCurrentFrameNumber',
        333: 'WdfUsbTargetDeviceSendControlTransferSynchronously',
        334: 'WdfUsbTargetDeviceFormatRequestForControlTransfer',
        335: 'WdfUsbTargetDeviceIsConnectedSynchronous',
        336: 'WdfUsbTargetDeviceResetPortSynchronously',
        337: 'WdfUsbTargetDeviceCyclePortSynchronously',
        338: 'WdfUsbTargetDeviceFormatRequestForCyclePort',
        339: 'WdfUsbTargetDeviceSendUrbSynchronously',
        340: 'WdfUsbTargetDeviceFormatRequestForUrb',
        341: 'WdfUsbTargetPipeGetInformation',
        342: 'WdfUsbTargetPipeIsInEndpoint',
        343: 'WdfUsbTargetPipeIsOutEndpoint',
        344: 'WdfUsbTargetPipeGetType',
        345: 'WdfUsbTargetPipeSetNoMaximumPacketSizeCheck',
        346: 'WdfUsbTargetPipeWriteSynchronously',
        347: 'WdfUsbTargetPipeFormatRequestForWrite',
        348: 'WdfUsbTargetPipeReadSynchronously',
        349: 'WdfUsbTargetPipeFormatRequestForRead',
        350: 'WdfUsbTargetPipeConfigContinuousReader',
        351: 'WdfUsbTargetPipeAbortSynchronously',
        352: 'WdfUsbTargetPipeFormatRequestForAbort',
        353: 'WdfUsbTargetPipeResetSynchronously',
        354: 'WdfUsbTargetPipeFormatRequestForReset',
        355: 'WdfUsbTargetPipeSendUrbSynchronously',
        356: 'WdfUsbTargetPipeFormatRequestForUrb',
        357: 'WdfUsbInterfaceGetInterfaceNumber',
        358: 'WdfUsbInterfaceGetNumEndpoints',
        359: 'WdfUsbInterfaceGetDescriptor',
        360: 'WdfUsbInterfaceSelectSetting',
        361: 'WdfUsbInterfaceGetEndpointInformation',
        362: 'WdfUsbTargetDeviceGetInterface',
        363: 'WdfUsbInterfaceGetConfiguredSettingIndex',
        364: 'WdfUsbInterfaceGetNumConfiguredPipes',
        365: 'WdfUsbInterfaceGetConfiguredPipe',
        366: 'WdfUsbTargetPipeWdmGetPipeHandle',
        367: 'WdfVerifierDbgBreakPoint',
        368: 'WdfVerifierKeBugCheck',
        369: 'WdfWmiProviderCreate',
        370: 'WdfWmiProviderGetDevice',
        371: 'WdfWmiProviderIsEnabled',
        372: 'WdfWmiProviderGetTracingHandle',
        373: 'WdfWmiInstanceCreate',
        374: 'WdfWmiInstanceRegister',
        375: 'WdfWmiInstanceDeregister',
        376: 'WdfWmiInstanceGetDevice',
        377: 'WdfWmiInstanceGetProvider',
        378: 'WdfWmiInstanceFireEvent',
        379: 'WdfWorkItemCreate',
        380: 'WdfWorkItemEnqueue',
        381: 'WdfWorkItemGetParentObject',
        382: 'WdfWorkItemFlush',
        383: 'WdfCommonBufferCreateWithConfig',
        384: 'WdfDmaEnablerGetFragmentLength',
        385: 'WdfDmaEnablerWdmGetDmaAdapter',
        386: 'WdfUsbInterfaceGetNumSettings',
        387: 'WdfDeviceRemoveDependentUsageDeviceObject',
        388: 'WdfDeviceGetSystemPowerAction',
        389: 'WdfInterruptSetExtendedPolicy',
        390: 'WdfIoQueueAssignForwardProgressPolicy',
        391: 'WdfPdoInitAssignContainerID',
        392: 'WdfPdoInitAllowForwardingRequestToParent',
        393: 'WdfRequestMarkCancelableEx',
        394: 'WdfRequestIsReserved',
        395: 'WdfRequestForwardToParentDeviceIoQueue',
        396: 'WdfCxDeviceInitAllocate',
        397: 'WdfCxDeviceInitAssignWdmIrpPreprocessCallback',
        398: 'WdfCxDeviceInitSetIoInCallerContextCallback',
        399: 'WdfCxDeviceInitSetRequestAttributes',
        400: 'WdfCxDeviceInitSetFileObjectConfig',
        401: 'WdfDeviceWdmDispatchIrp',
        402: 'WdfDeviceWdmDispatchIrpToIoQueue',
        403: 'WdfDeviceInitSetRemoveLockOptions',
        404: 'WdfDeviceConfigureWdmIrpDispatchCallback',
        405: 'WdfDmaEnablerConfigureSystemProfile',
        406: 'WdfDmaTransactionInitializeUsingOffset',
        407: 'WdfDmaTransactionGetTransferInfo',
        408: 'WdfDmaTransactionSetChannelConfigurationCallback',
        409: 'WdfDmaTransactionSetTransferCompleteCallback',
        410: 'WdfDmaTransactionSetImmediateExecution',
        411: 'WdfDmaTransactionAllocateResources',
        412: 'WdfDmaTransactionSetDeviceAddressOffset',
        413: 'WdfDmaTransactionFreeResources',
        414: 'WdfDmaTransactionCancel',
        415: 'WdfDmaTransactionWdmGetTransferContext',
        416: 'WdfInterruptQueueWorkItemForIsr',
        417: 'WdfInterruptTryToAcquireLock',
        418: 'WdfIoQueueStopAndPurge',
        419: 'WdfIoQueueStopAndPurgeSynchronously',
        420: 'WdfIoTargetPurge',
        421: 'WdfUsbTargetDeviceCreateWithParameters',
        422: 'WdfUsbTargetDeviceQueryUsbCapability',
        423: 'WdfUsbTargetDeviceCreateUrb',
        424: 'WdfUsbTargetDeviceCreateIsochUrb',
        425: 'WdfDeviceWdmAssignPowerFrameworkSettings',
        426: 'WdfDmaTransactionStopSystemTransfer',
        427: 'WdfCxVerifierKeBugCheck',
        428: 'WdfInterruptReportActive',
        429: 'WdfInterruptReportInactive',
        430: 'WdfDeviceInitSetReleaseHardwareOrderOnFailure',
        431: 'WdfGetTriageInfo',
        432: 'WdfDeviceInitSetIoTypeEx',
        433: 'WdfDeviceQueryPropertyEx',
        434: 'WdfDeviceAllocAndQueryPropertyEx',
        435: 'WdfDeviceAssignProperty',
        436: 'WdfFdoInitQueryPropertyEx',
        437: 'WdfFdoInitAllocAndQueryPropertyEx',
        438: 'WdfDeviceStopIdleActual',
        439: 'WdfDeviceResumeIdleActual',
        440: 'WdfDeviceGetSelfIoTarget',
        441: 'WdfDeviceInitAllowSelfIoTarget',
        442: 'WdfIoTargetSelfAssignDefaultIoQueue',
        443: 'WdfDeviceOpenDevicemapKey',
        444: 'WdfDmaTransactionSetSingleTransferRequirement',
        445: 'WdfCxDeviceInitSetPnpPowerEventCallbacks',
        446: 'WdfFileObjectGetInitiatorProcessId',
        447: 'WdfRequestGetRequestorProcessId',
        448: 'WdfDeviceRetrieveCompanionTarget',
        449: 'WdfCompanionTargetSendTaskSynchronously',
        450: 'WdfCompanionTargetWdmGetCompanionProcess',
        451: 'WdfDriverOpenPersistentStateRegistryKey',
        452: 'WdfDriverErrorReportApiMissing',
        453: 'WdfPdoInitRemovePowerDependencyOnParent',
        454: 'WdfCxDeviceInitAllocateContext',
        455: 'WdfCxDeviceInitGetTypedContextWorker',
        456: 'WdfCxDeviceInitSetPowerPolicyEventCallbacks',
        457: 'WdfDeviceSetDeviceInterfaceStateEx',
        458: 'WdfFunctionTableNumEntries',
    }
    return switcher.get(id, 'Unknow name')


# 根据函数索引取函数名字
def GetNameByID_01015(id):
    switcher = {
        0: 'WdfChildListCreate',
        1: 'WdfChildListGetDevice',
        2: 'WdfChildListRetrievePdo',
        3: 'WdfChildListRetrieveAddressDescription',
        4: 'WdfChildListBeginScan',
        5: 'WdfChildListEndScan',
        6: 'WdfChildListBeginIteration',
        7: 'WdfChildListRetrieveNextDevice',
        8: 'WdfChildListEndIteration',
        9: 'WdfChildListAddOrUpdateChildDescriptionAsPresent',
        10: 'WdfChildListUpdateChildDescriptionAsMissing',
        11: 'WdfChildListUpdateAllChildDescriptionsAsPresent',
        12: 'WdfChildListRequestChildEject',
        13: 'WdfCollectionCreate',
        14: 'WdfCollectionGetCount',
        15: 'WdfCollectionAdd',
        16: 'WdfCollectionRemove',
        17: 'WdfCollectionRemoveItem',
        18: 'WdfCollectionGetItem',
        19: 'WdfCollectionGetFirstItem',
        20: 'WdfCollectionGetLastItem',
        21: 'WdfCommonBufferCreate',
        22: 'WdfCommonBufferGetAlignedVirtualAddress',
        23: 'WdfCommonBufferGetAlignedLogicalAddress',
        24: 'WdfCommonBufferGetLength',
        25: 'WdfControlDeviceInitAllocate',
        26: 'WdfControlDeviceInitSetShutdownNotification',
        27: 'WdfControlFinishInitializing',
        28: 'WdfDeviceGetDeviceState',
        29: 'WdfDeviceSetDeviceState',
        30: 'WdfWdmDeviceGetWdfDeviceHandle',
        31: 'WdfDeviceWdmGetDeviceObject',
        32: 'WdfDeviceWdmGetAttachedDevice',
        33: 'WdfDeviceWdmGetPhysicalDevice',
        34: 'WdfDeviceWdmDispatchPreprocessedIrp',
        35: 'WdfDeviceAddDependentUsageDeviceObject',
        36: 'WdfDeviceAddRemovalRelationsPhysicalDevice',
        37: 'WdfDeviceRemoveRemovalRelationsPhysicalDevice',
        38: 'WdfDeviceClearRemovalRelationsDevices',
        39: 'WdfDeviceGetDriver',
        40: 'WdfDeviceRetrieveDeviceName',
        41: 'WdfDeviceAssignMofResourceName',
        42: 'WdfDeviceGetIoTarget',
        43: 'WdfDeviceGetDevicePnpState',
        44: 'WdfDeviceGetDevicePowerState',
        45: 'WdfDeviceGetDevicePowerPolicyState',
        46: 'WdfDeviceAssignS0IdleSettings',
        47: 'WdfDeviceAssignSxWakeSettings',
        48: 'WdfDeviceOpenRegistryKey',
        49: 'WdfDeviceSetSpecialFileSupport',
        50: 'WdfDeviceSetCharacteristics',
        51: 'WdfDeviceGetCharacteristics',
        52: 'WdfDeviceGetAlignmentRequirement',
        53: 'WdfDeviceSetAlignmentRequirement',
        54: 'WdfDeviceInitFree',
        55: 'WdfDeviceInitSetPnpPowerEventCallbacks',
        56: 'WdfDeviceInitSetPowerPolicyEventCallbacks',
        57: 'WdfDeviceInitSetPowerPolicyOwnership',
        58: 'WdfDeviceInitRegisterPnpStateChangeCallback',
        59: 'WdfDeviceInitRegisterPowerStateChangeCallback',
        60: 'WdfDeviceInitRegisterPowerPolicyStateChangeCallback',
        61: 'WdfDeviceInitSetIoType',
        62: 'WdfDeviceInitSetExclusive',
        63: 'WdfDeviceInitSetPowerNotPageable',
        64: 'WdfDeviceInitSetPowerPageable',
        65: 'WdfDeviceInitSetPowerInrush',
        66: 'WdfDeviceInitSetDeviceType',
        67: 'WdfDeviceInitAssignName',
        68: 'WdfDeviceInitAssignSDDLString',
        69: 'WdfDeviceInitSetDeviceClass',
        70: 'WdfDeviceInitSetCharacteristics',
        71: 'WdfDeviceInitSetFileObjectConfig',
        72: 'WdfDeviceInitSetRequestAttributes',
        73: 'WdfDeviceInitAssignWdmIrpPreprocessCallback',
        74: 'WdfDeviceInitSetIoInCallerContextCallback',
        75: 'WdfDeviceCreate',
        76: 'WdfDeviceSetStaticStopRemove',
        77: 'WdfDeviceCreateDeviceInterface',
        78: 'WdfDeviceSetDeviceInterfaceState',
        79: 'WdfDeviceRetrieveDeviceInterfaceString',
        80: 'WdfDeviceCreateSymbolicLink',
        81: 'WdfDeviceQueryProperty',
        82: 'WdfDeviceAllocAndQueryProperty',
        83: 'WdfDeviceSetPnpCapabilities',
        84: 'WdfDeviceSetPowerCapabilities',
        85: 'WdfDeviceSetBusInformationForChildren',
        86: 'WdfDeviceIndicateWakeStatus',
        87: 'WdfDeviceSetFailed',
        88: 'WdfDeviceStopIdleNoTrack',
        89: 'WdfDeviceResumeIdleNoTrack',
        90: 'WdfDeviceGetFileObject',
        91: 'WdfDeviceEnqueueRequest',
        92: 'WdfDeviceGetDefaultQueue',
        93: 'WdfDeviceConfigureRequestDispatching',
        94: 'WdfDmaEnablerCreate',
        95: 'WdfDmaEnablerGetMaximumLength',
        96: 'WdfDmaEnablerGetMaximumScatterGatherElements',
        97: 'WdfDmaEnablerSetMaximumScatterGatherElements',
        98: 'WdfDmaTransactionCreate',
        99: 'WdfDmaTransactionInitialize',
        100: 'WdfDmaTransactionInitializeUsingRequest',
        101: 'WdfDmaTransactionExecute',
        102: 'WdfDmaTransactionRelease',
        103: 'WdfDmaTransactionDmaCompleted',
        104: 'WdfDmaTransactionDmaCompletedWithLength',
        105: 'WdfDmaTransactionDmaCompletedFinal',
        106: 'WdfDmaTransactionGetBytesTransferred',
        107: 'WdfDmaTransactionSetMaximumLength',
        108: 'WdfDmaTransactionGetRequest',
        109: 'WdfDmaTransactionGetCurrentDmaTransferLength',
        110: 'WdfDmaTransactionGetDevice',
        111: 'WdfDpcCreate',
        112: 'WdfDpcEnqueue',
        113: 'WdfDpcCancel',
        114: 'WdfDpcGetParentObject',
        115: 'WdfDpcWdmGetDpc',
        116: 'WdfDriverCreate',
        117: 'WdfDriverGetRegistryPath',
        118: 'WdfDriverWdmGetDriverObject',
        119: 'WdfDriverOpenParametersRegistryKey',
        120: 'WdfWdmDriverGetWdfDriverHandle',
        121: 'WdfDriverRegisterTraceInfo',
        122: 'WdfDriverRetrieveVersionString',
        123: 'WdfDriverIsVersionAvailable',
        124: 'WdfFdoInitWdmGetPhysicalDevice',
        125: 'WdfFdoInitOpenRegistryKey',
        126: 'WdfFdoInitQueryProperty',
        127: 'WdfFdoInitAllocAndQueryProperty',
        128: 'WdfFdoInitSetEventCallbacks',
        129: 'WdfFdoInitSetFilter',
        130: 'WdfFdoInitSetDefaultChildListConfig',
        131: 'WdfFdoQueryForInterface',
        132: 'WdfFdoGetDefaultChildList',
        133: 'WdfFdoAddStaticChild',
        134: 'WdfFdoLockStaticChildListForIteration',
        135: 'WdfFdoRetrieveNextStaticChild',
        136: 'WdfFdoUnlockStaticChildListFromIteration',
        137: 'WdfFileObjectGetFileName',
        138: 'WdfFileObjectGetFlags',
        139: 'WdfFileObjectGetDevice',
        140: 'WdfFileObjectWdmGetFileObject',
        141: 'WdfInterruptCreate',
        142: 'WdfInterruptQueueDpcForIsr',
        143: 'WdfInterruptSynchronize',
        144: 'WdfInterruptAcquireLock',
        145: 'WdfInterruptReleaseLock',
        146: 'WdfInterruptEnable',
        147: 'WdfInterruptDisable',
        148: 'WdfInterruptWdmGetInterrupt',
        149: 'WdfInterruptGetInfo',
        150: 'WdfInterruptSetPolicy',
        151: 'WdfInterruptGetDevice',
        152: 'WdfIoQueueCreate',
        153: 'WdfIoQueueGetState',
        154: 'WdfIoQueueStart',
        155: 'WdfIoQueueStop',
        156: 'WdfIoQueueStopSynchronously',
        157: 'WdfIoQueueGetDevice',
        158: 'WdfIoQueueRetrieveNextRequest',
        159: 'WdfIoQueueRetrieveRequestByFileObject',
        160: 'WdfIoQueueFindRequest',
        161: 'WdfIoQueueRetrieveFoundRequest',
        162: 'WdfIoQueueDrainSynchronously',
        163: 'WdfIoQueueDrain',
        164: 'WdfIoQueuePurgeSynchronously',
        165: 'WdfIoQueuePurge',
        166: 'WdfIoQueueReadyNotify',
        167: 'WdfIoTargetCreate',
        168: 'WdfIoTargetOpen',
        169: 'WdfIoTargetCloseForQueryRemove',
        170: 'WdfIoTargetClose',
        171: 'WdfIoTargetStart',
        172: 'WdfIoTargetStop',
        173: 'WdfIoTargetGetState',
        174: 'WdfIoTargetGetDevice',
        175: 'WdfIoTargetQueryTargetProperty',
        176: 'WdfIoTargetAllocAndQueryTargetProperty',
        177: 'WdfIoTargetQueryForInterface',
        178: 'WdfIoTargetWdmGetTargetDeviceObject',
        179: 'WdfIoTargetWdmGetTargetPhysicalDevice',
        180: 'WdfIoTargetWdmGetTargetFileObject',
        181: 'WdfIoTargetWdmGetTargetFileHandle',
        182: 'WdfIoTargetSendReadSynchronously',
        183: 'WdfIoTargetFormatRequestForRead',
        184: 'WdfIoTargetSendWriteSynchronously',
        185: 'WdfIoTargetFormatRequestForWrite',
        186: 'WdfIoTargetSendIoctlSynchronously',
        187: 'WdfIoTargetFormatRequestForIoctl',
        188: 'WdfIoTargetSendInternalIoctlSynchronously',
        189: 'WdfIoTargetFormatRequestForInternalIoctl',
        190: 'WdfIoTargetSendInternalIoctlOthersSynchronously',
        191: 'WdfIoTargetFormatRequestForInternalIoctlOthers',
        192: 'WdfMemoryCreate',
        193: 'WdfMemoryCreatePreallocated',
        194: 'WdfMemoryGetBuffer',
        195: 'WdfMemoryAssignBuffer',
        196: 'WdfMemoryCopyToBuffer',
        197: 'WdfMemoryCopyFromBuffer',
        198: 'WdfLookasideListCreate',
        199: 'WdfMemoryCreateFromLookaside',
        200: 'WdfDeviceMiniportCreate',
        201: 'WdfDriverMiniportUnload',
        202: 'WdfObjectGetTypedContextWorker',
        203: 'WdfObjectAllocateContext',
        204: 'WdfObjectContextGetObject',
        205: 'WdfObjectReferenceActual',
        206: 'WdfObjectDereferenceActual',
        207: 'WdfObjectCreate',
        208: 'WdfObjectDelete',
        209: 'WdfObjectQuery',
        210: 'WdfPdoInitAllocate',
        211: 'WdfPdoInitSetEventCallbacks',
        212: 'WdfPdoInitAssignDeviceID',
        213: 'WdfPdoInitAssignInstanceID',
        214: 'WdfPdoInitAddHardwareID',
        215: 'WdfPdoInitAddCompatibleID',
        216: 'WdfPdoInitAddDeviceText',
        217: 'WdfPdoInitSetDefaultLocale',
        218: 'WdfPdoInitAssignRawDevice',
        219: 'WdfPdoMarkMissing',
        220: 'WdfPdoRequestEject',
        221: 'WdfPdoGetParent',
        222: 'WdfPdoRetrieveIdentificationDescription',
        223: 'WdfPdoRetrieveAddressDescription',
        224: 'WdfPdoUpdateAddressDescription',
        225: 'WdfPdoAddEjectionRelationsPhysicalDevice',
        226: 'WdfPdoRemoveEjectionRelationsPhysicalDevice',
        227: 'WdfPdoClearEjectionRelationsDevices',
        228: 'WdfDeviceAddQueryInterface',
        229: 'WdfRegistryOpenKey',
        230: 'WdfRegistryCreateKey',
        231: 'WdfRegistryClose',
        232: 'WdfRegistryWdmGetHandle',
        233: 'WdfRegistryRemoveKey',
        234: 'WdfRegistryRemoveValue',
        235: 'WdfRegistryQueryValue',
        236: 'WdfRegistryQueryMemory',
        237: 'WdfRegistryQueryMultiString',
        238: 'WdfRegistryQueryUnicodeString',
        239: 'WdfRegistryQueryString',
        240: 'WdfRegistryQueryULong',
        241: 'WdfRegistryAssignValue',
        242: 'WdfRegistryAssignMemory',
        243: 'WdfRegistryAssignMultiString',
        244: 'WdfRegistryAssignUnicodeString',
        245: 'WdfRegistryAssignString',
        246: 'WdfRegistryAssignULong',
        247: 'WdfRequestCreate',
        248: 'WdfRequestCreateFromIrp',
        249: 'WdfRequestReuse',
        250: 'WdfRequestChangeTarget',
        251: 'WdfRequestFormatRequestUsingCurrentType',
        252: 'WdfRequestWdmFormatUsingStackLocation',
        253: 'WdfRequestSend',
        254: 'WdfRequestGetStatus',
        255: 'WdfRequestMarkCancelable',
        256: 'WdfRequestUnmarkCancelable',
        257: 'WdfRequestIsCanceled',
        258: 'WdfRequestCancelSentRequest',
        259: 'WdfRequestIsFrom32BitProcess',
        260: 'WdfRequestSetCompletionRoutine',
        261: 'WdfRequestGetCompletionParams',
        262: 'WdfRequestAllocateTimer',
        263: 'WdfRequestComplete',
        264: 'WdfRequestCompleteWithPriorityBoost',
        265: 'WdfRequestCompleteWithInformation',
        266: 'WdfRequestGetParameters',
        267: 'WdfRequestRetrieveInputMemory',
        268: 'WdfRequestRetrieveOutputMemory',
        269: 'WdfRequestRetrieveInputBuffer',
        270: 'WdfRequestRetrieveOutputBuffer',
        271: 'WdfRequestRetrieveInputWdmMdl',
        272: 'WdfRequestRetrieveOutputWdmMdl',
        273: 'WdfRequestRetrieveUnsafeUserInputBuffer',
        274: 'WdfRequestRetrieveUnsafeUserOutputBuffer',
        275: 'WdfRequestSetInformation',
        276: 'WdfRequestGetInformation',
        277: 'WdfRequestGetFileObject',
        278: 'WdfRequestProbeAndLockUserBufferForRead',
        279: 'WdfRequestProbeAndLockUserBufferForWrite',
        280: 'WdfRequestGetRequestorMode',
        281: 'WdfRequestForwardToIoQueue',
        282: 'WdfRequestGetIoQueue',
        283: 'WdfRequestRequeue',
        284: 'WdfRequestStopAcknowledge',
        285: 'WdfRequestWdmGetIrp',
        286: 'WdfIoResourceRequirementsListSetSlotNumber',
        287: 'WdfIoResourceRequirementsListSetInterfaceType',
        288: 'WdfIoResourceRequirementsListAppendIoResList',
        289: 'WdfIoResourceRequirementsListInsertIoResList',
        290: 'WdfIoResourceRequirementsListGetCount',
        291: 'WdfIoResourceRequirementsListGetIoResList',
        292: 'WdfIoResourceRequirementsListRemove',
        293: 'WdfIoResourceRequirementsListRemoveByIoResList',
        294: 'WdfIoResourceListCreate',
        295: 'WdfIoResourceListAppendDescriptor',
        296: 'WdfIoResourceListInsertDescriptor',
        297: 'WdfIoResourceListUpdateDescriptor',
        298: 'WdfIoResourceListGetCount',
        299: 'WdfIoResourceListGetDescriptor',
        300: 'WdfIoResourceListRemove',
        301: 'WdfIoResourceListRemoveByDescriptor',
        302: 'WdfCmResourceListAppendDescriptor',
        303: 'WdfCmResourceListInsertDescriptor',
        304: 'WdfCmResourceListGetCount',
        305: 'WdfCmResourceListGetDescriptor',
        306: 'WdfCmResourceListRemove',
        307: 'WdfCmResourceListRemoveByDescriptor',
        308: 'WdfStringCreate',
        309: 'WdfStringGetUnicodeString',
        310: 'WdfObjectAcquireLock',
        311: 'WdfObjectReleaseLock',
        312: 'WdfWaitLockCreate',
        313: 'WdfWaitLockAcquire',
        314: 'WdfWaitLockRelease',
        315: 'WdfSpinLockCreate',
        316: 'WdfSpinLockAcquire',
        317: 'WdfSpinLockRelease',
        318: 'WdfTimerCreate',
        319: 'WdfTimerStart',
        320: 'WdfTimerStop',
        321: 'WdfTimerGetParentObject',
        322: 'WdfUsbTargetDeviceCreate',
        323: 'WdfUsbTargetDeviceRetrieveInformation',
        324: 'WdfUsbTargetDeviceGetDeviceDescriptor',
        325: 'WdfUsbTargetDeviceRetrieveConfigDescriptor',
        326: 'WdfUsbTargetDeviceQueryString',
        327: 'WdfUsbTargetDeviceAllocAndQueryString',
        328: 'WdfUsbTargetDeviceFormatRequestForString',
        329: 'WdfUsbTargetDeviceGetNumInterfaces',
        330: 'WdfUsbTargetDeviceSelectConfig',
        331: 'WdfUsbTargetDeviceWdmGetConfigurationHandle',
        332: 'WdfUsbTargetDeviceRetrieveCurrentFrameNumber',
        333: 'WdfUsbTargetDeviceSendControlTransferSynchronously',
        334: 'WdfUsbTargetDeviceFormatRequestForControlTransfer',
        335: 'WdfUsbTargetDeviceIsConnectedSynchronous',
        336: 'WdfUsbTargetDeviceResetPortSynchronously',
        337: 'WdfUsbTargetDeviceCyclePortSynchronously',
        338: 'WdfUsbTargetDeviceFormatRequestForCyclePort',
        339: 'WdfUsbTargetDeviceSendUrbSynchronously',
        340: 'WdfUsbTargetDeviceFormatRequestForUrb',
        341: 'WdfUsbTargetPipeGetInformation',
        342: 'WdfUsbTargetPipeIsInEndpoint',
        343: 'WdfUsbTargetPipeIsOutEndpoint',
        344: 'WdfUsbTargetPipeGetType',
        345: 'WdfUsbTargetPipeSetNoMaximumPacketSizeCheck',
        346: 'WdfUsbTargetPipeWriteSynchronously',
        347: 'WdfUsbTargetPipeFormatRequestForWrite',
        348: 'WdfUsbTargetPipeReadSynchronously',
        349: 'WdfUsbTargetPipeFormatRequestForRead',
        350: 'WdfUsbTargetPipeConfigContinuousReader',
        351: 'WdfUsbTargetPipeAbortSynchronously',
        352: 'WdfUsbTargetPipeFormatRequestForAbort',
        353: 'WdfUsbTargetPipeResetSynchronously',
        354: 'WdfUsbTargetPipeFormatRequestForReset',
        355: 'WdfUsbTargetPipeSendUrbSynchronously',
        356: 'WdfUsbTargetPipeFormatRequestForUrb',
        357: 'WdfUsbInterfaceGetInterfaceNumber',
        358: 'WdfUsbInterfaceGetNumEndpoints',
        359: 'WdfUsbInterfaceGetDescriptor',
        360: 'WdfUsbInterfaceSelectSetting',
        361: 'WdfUsbInterfaceGetEndpointInformation',
        362: 'WdfUsbTargetDeviceGetInterface',
        363: 'WdfUsbInterfaceGetConfiguredSettingIndex',
        364: 'WdfUsbInterfaceGetNumConfiguredPipes',
        365: 'WdfUsbInterfaceGetConfiguredPipe',
        366: 'WdfUsbTargetPipeWdmGetPipeHandle',
        367: 'WdfVerifierDbgBreakPoint',
        368: 'WdfVerifierKeBugCheck',
        369: 'WdfWmiProviderCreate',
        370: 'WdfWmiProviderGetDevice',
        371: 'WdfWmiProviderIsEnabled',
        372: 'WdfWmiProviderGetTracingHandle',
        373: 'WdfWmiInstanceCreate',
        374: 'WdfWmiInstanceRegister',
        375: 'WdfWmiInstanceDeregister',
        376: 'WdfWmiInstanceGetDevice',
        377: 'WdfWmiInstanceGetProvider',
        378: 'WdfWmiInstanceFireEvent',
        379: 'WdfWorkItemCreate',
        380: 'WdfWorkItemEnqueue',
        381: 'WdfWorkItemGetParentObject',
        382: 'WdfWorkItemFlush',
        383: 'WdfCommonBufferCreateWithConfig',
        384: 'WdfDmaEnablerGetFragmentLength',
        385: 'WdfDmaEnablerWdmGetDmaAdapter',
        386: 'WdfUsbInterfaceGetNumSettings',
        387: 'WdfDeviceRemoveDependentUsageDeviceObject',
        388: 'WdfDeviceGetSystemPowerAction',
        389: 'WdfInterruptSetExtendedPolicy',
        390: 'WdfIoQueueAssignForwardProgressPolicy',
        391: 'WdfPdoInitAssignContainerID',
        392: 'WdfPdoInitAllowForwardingRequestToParent',
        393: 'WdfRequestMarkCancelableEx',
        394: 'WdfRequestIsReserved',
        395: 'WdfRequestForwardToParentDeviceIoQueue',
        396: 'WdfCxDeviceInitAllocate',
        397: 'WdfCxDeviceInitAssignWdmIrpPreprocessCallback',
        398: 'WdfCxDeviceInitSetIoInCallerContextCallback',
        399: 'WdfCxDeviceInitSetRequestAttributes',
        400: 'WdfCxDeviceInitSetFileObjectConfig',
        401: 'WdfDeviceWdmDispatchIrp',
        402: 'WdfDeviceWdmDispatchIrpToIoQueue',
        403: 'WdfDeviceInitSetRemoveLockOptions',
        404: 'WdfDeviceConfigureWdmIrpDispatchCallback',
        405: 'WdfDmaEnablerConfigureSystemProfile',
        406: 'WdfDmaTransactionInitializeUsingOffset',
        407: 'WdfDmaTransactionGetTransferInfo',
        408: 'WdfDmaTransactionSetChannelConfigurationCallback',
        409: 'WdfDmaTransactionSetTransferCompleteCallback',
        410: 'WdfDmaTransactionSetImmediateExecution',
        411: 'WdfDmaTransactionAllocateResources',
        412: 'WdfDmaTransactionSetDeviceAddressOffset',
        413: 'WdfDmaTransactionFreeResources',
        414: 'WdfDmaTransactionCancel',
        415: 'WdfDmaTransactionWdmGetTransferContext',
        416: 'WdfInterruptQueueWorkItemForIsr',
        417: 'WdfInterruptTryToAcquireLock',
        418: 'WdfIoQueueStopAndPurge',
        419: 'WdfIoQueueStopAndPurgeSynchronously',
        420: 'WdfIoTargetPurge',
        421: 'WdfUsbTargetDeviceCreateWithParameters',
        422: 'WdfUsbTargetDeviceQueryUsbCapability',
        423: 'WdfUsbTargetDeviceCreateUrb',
        424: 'WdfUsbTargetDeviceCreateIsochUrb',
        425: 'WdfDeviceWdmAssignPowerFrameworkSettings',
        426: 'WdfDmaTransactionStopSystemTransfer',
        427: 'WdfCxVerifierKeBugCheck',
        428: 'WdfInterruptReportActive',
        429: 'WdfInterruptReportInactive',
        430: 'WdfDeviceInitSetReleaseHardwareOrderOnFailure',
        431: 'WdfGetTriageInfo',
        432: 'WdfDeviceInitSetIoTypeEx',
        433: 'WdfDeviceQueryPropertyEx',
        434: 'WdfDeviceAllocAndQueryPropertyEx',
        435: 'WdfDeviceAssignProperty',
        436: 'WdfFdoInitQueryPropertyEx',
        437: 'WdfFdoInitAllocAndQueryPropertyEx',
        438: 'WdfDeviceStopIdleActual',
        439: 'WdfDeviceResumeIdleActual',
        440: 'WdfDeviceGetSelfIoTarget',
        441: 'WdfDeviceInitAllowSelfIoTarget',
        442: 'WdfIoTargetSelfAssignDefaultIoQueue',
        443: 'WdfDeviceOpenDevicemapKey',
        444: 'WdfFunctionTableNumEntries',
    }
    return switcher.get(id, 'Unknow name')


_verBig = 0
_verMin = 0


def GetNameByID(id):
    if str(_verBig) == "1":
        if str(_verMin) == "15":
            return GetNameByID_01015(id)
        if str(_verMin) == "31":
            return GetNameByID_01031(id)
    return "Unknow name"


# 第一种方式获取函数名
def ReMakeWdfFunctionName1(cur_addr):
    pre_addr = idc.prev_head(cur_addr)
    pre_asm = GetDisasm(pre_addr)
    # print("pre", pre_addr, pre_asm)
    # 第一种情况，上一条是一个乘法指令，功能是计算基址加索引
    if pre_asm.startswith("imul"):
        # 第 0 个参数类型是1，所以是寄存器
        type0 = idc.get_operand_type(pre_addr, 0)
        if type0 != 1:
            return False
        # 寄存器参数索引是 0，是rax
        data = idc.get_operand_value(pre_addr, 0)
        if data != 0:
            return False

        # 按理说应该是取操作数1，但是这里1里面没值，所以取的是 2
        # 取出来的就是函数索引
        data = idc.get_operand_value(pre_addr, 2)

        # 根据函数索引
        func_name = GetNameByID(data)

        fun_addr = idc.get_func_attr(pre_addr, FUNCATTR_START)
        # print(fun_addr)

        print("address %#x" % cur_addr, " [", GetDisasm(cur_addr), "] : ", data)

        if func_name != "":
            ida_name.set_name(fun_addr, func_name)
            return True
    return False


def GetNextCallFunction(cur_addr, str_name, _max=100):
    for i in range(0, _max):
        cur_addr = idc.next_head(cur_addr)
        next_asm = GetDisasm(cur_addr)
        if next_asm.startswith("call"):
            if next_asm.find(str_name) != -1:
                print("       ", next_asm)
                return cur_addr
    return 0


def GetCurrentMovRaxValueIndex(cur_addr):
    pre_asm = GetDisasm(cur_addr)
    if pre_asm.startswith("mov"):
        # 第 0 个参数类型是1，所以是寄存器
        type0 = idc.get_operand_type(cur_addr, 0)
        if type0 != 1:
            return -1
        # 寄存器参数索引是 0，是rax
        data = idc.get_operand_value(cur_addr, 0)
        if data != 0:
            return -1
        # 第 0 个参数类型是1，所以是寄存器
        type0 = idc.get_operand_type(cur_addr, 1)
        if type0 != 4:
            return -1
        data = idc.get_operand_value(cur_addr, 1)
        return data / 8
    return -1


def GetCurrentMovRaxValueIndex2(cur_addr, reg_val, _max=100):
    opt_type = 1
    cur_addr = idc.next_head(cur_addr)
    for i in range(0, _max):
        cur_addr = idc.prev_head(cur_addr)
        pre_asm = GetDisasm(cur_addr)
        if pre_asm.startswith("mov"):
            # 第 0 个参数类型是1，所以是寄存器
            type0 = idc.get_operand_type(cur_addr, 0)
            if type0 != opt_type:
                continue
            # 寄存器参数索引是 0，是rax
            data = idc.get_operand_value(cur_addr, 0)
            if data != reg_val:
                continue
            # 第 0 个参数类型是1，所以是寄存器
            type0 = idc.get_operand_type(cur_addr, 1)
            data = idc.get_operand_value(cur_addr, 1)
            # print("    --- 2 %#x" % cur_addr, " : ", type0, " : ", data, " [", GetDisasm(cur_addr), "]", " : ", GetOperandTypeName(type0))
            if type0 == 1:
                reg_val = data
                continue
            elif type0 == 4:
                return data / 8

    return -1


def GetPreMovRax(cur_addr, reg_val, _max=100):
    for i in range(0, _max):
        cur_addr = idc.prev_head(cur_addr)
        pre_asm = GetDisasm(cur_addr)
        if pre_asm.startswith("mov"):
            # 第 0 个参数类型是1，所以是寄存器
            type0 = idc.get_operand_type(cur_addr, 0)
            if type0 != 1:
                continue
            # 寄存器参数索引是 0，是rax
            data = idc.get_operand_value(cur_addr, 0)
            if data != reg_val:
                continue

            # print("    --- 1 %#x" % cur_addr, " : ", type0, " : ", GetOperandTypeName(type0), " : ", data, " [", GetDisasm(cur_addr), "]")
            return cur_addr
    return 0


# 第二种方式获取函数名
def ReMakeWdfFunctionName2(cur_addr):
    # 第二种情况，下面十几行之内，有一条call __guard_dispatch_icall_fptr
    # __guard_dispatch_icall_fptr 的上一行是个mov eax, xxxxx
    # 然后继续向上解析 xxxxxx

    # 第一步，先循环向下，找到最近的一个 call __guard_dispatch_icall_fptr
    # 最多找100条汇编
    next_addr = GetNextCallFunction(cur_addr, "__guard_dispatch_icall_fptr")
    # next_asm = GetDisasm(cur_addr)

    # 第二步，循环向前找，找到最后一个 mov rax, XXXXXXXX
    pre_addr = GetPreMovRax(next_addr, 0)
    if pre_addr == 0:
        print("    --- error cur", next_addr)
        return False

    index = GetCurrentMovRaxValueIndex(pre_addr)
    # mov     rax, [rcx+610h]
    if index == -1:
        # 如果取的不对，那么说明问题更复杂了，参数2 可能是个寄存器，可能不是个值
        # mov     rax, r9
        index = GetCurrentMovRaxValueIndex2(pre_addr, 0)
        if index == -1:
            pass
        pass

    # 根据函数索引取名字
    func_name = GetNameByID(index)

    set_cmt(cur_addr, func_name, 0)
    print("address %#x" % cur_addr, " [", GetDisasm(cur_addr), "] : ", index, func_name)
    return True


# 修复 WDF 函数信息
def MakeWdfFunctionInfo(addr):
    for x in XrefsTo(addr, flags=0):
        cur_addr = x.frm
        cur_asm = GetDisasm(cur_addr)
        if cur_asm.startswith("mov"):
            pass
        else:
            continue

        if ReMakeWdfFunctionName1(cur_addr) is True:
            continue

        if ReMakeWdfFunctionName2(cur_addr) is True:
            continue

        return


# 获取 WDF 版本号
def GetWdfVersionObject(pObject):
    verBig = idaapi.get_dword(pObject + 0x10)
    verMin = idaapi.get_dword(pObject + 0x14)
    return verBig, verMin


def MainFunction():
    base_address = idaapi.get_imagebase()
    print('Module Base Address : %#x' % base_address)
    start_address = base_address

    # 从模块中找到对应符号地址
    fpWdfVersionBind = idc.get_name_ea(start_address, "WdfVersionBind")
    print('Address : WdfVersionBind : %#x' % fpWdfVersionBind)

    if fpWdfVersionBind == 0xffffffffffffffff:
        # wdf 没发现，这里换个方式重新找
        print("Error : WdfVersionBind not found， use __imp_WdfVersionBind")
        fpWdfVersionBind = idc.get_name_ea(start_address, "__imp_WdfVersionBind")
        print('Address : __imp_WdfVersionBind : %#x' % fpWdfVersionBind)

    if fpWdfVersionBind == 0xffffffffffffffff:
        print("maybe not WDF Module")
        return

    # 根据对应符号地址，找到其第三个参数地址
    pObject = GetWdfVersionBindObject(fpWdfVersionBind)
    print('Address : Wdf Object : %#x' % pObject)
    if pObject != 0:
        # 获取的版本号
        global _verBig
        global _verMin
        _verBig, _verMin = GetWdfVersionObject(pObject)
        print("version :", _verBig, _verMin)

        # 寻找所有使用到的地方，并且修正对应函数名，编程索引对应函数名
        MakeWdfFunctionInfo(get_qword(pObject + 0x20))

        print("WDF Function Name Remake Success")


MainFunction()
