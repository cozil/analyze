//文件必须保存为utf8格式，否则在x64dbg日志输出中文会出现乱码

rule main_start
{
	meta:
		script = "log \"Start running script!\""
	condition:
		true
}

include "e:/rxwg/analyze/address.yar"
include "e:/rxwg/analyze/CRxMgrLogin.yar"
include "e:/rxwg/analyze/CRxSelf.yar"
include "e:/rxwg/analyze/CRxApp.yar"
include "e:/rxwg/analyze/CRxMgrNpc.yar"
include "e:/rxwg/analyze/CRxMgrShop.yar"
include "E:/rxwg/analyze/CRxMgrPk.yar"
include "E:/rxwg/analyze/CRxMgrZd.yar"
include "E:/rxwg/analyze/CRxMgrThl.yar"
include "E:/rxwg/analyze/CRxMgrConfig.yar"
include "E:/rxwg/analyze/CRxMgrState.yar"
include "E:/rxwg/analyze/CRxMgrCharm.yar"
include "E:/rxwg/analyze/CRxNpc.yar"
include "E:/rxwg/analyze/CRxPlayer.yar"
include "E:/rxwg/analyze/CRxGroundStuff.yar"
include "E:/rxwg/analyze/CRxStuff.yar"
include "E:/rxwg/analyze/CRxPicker.yar"
include "E:/rxwg/analyze/CRxSocket.yar"

rule main_finish
{
	meta:
		script = "log \"Running script finished!\""
	condition:
		true
}

