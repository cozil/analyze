//文件必须保存为utf8格式，否则在x64dbg日志输出中文会出现乱码

rule main_start
{
	meta:
		script = "log \"Start running script!\""
		script = "yaraEx.ll 1"
		script = "Type.removeAll"
		script = "Array.removeAll"
		load = "utils/basicStructs.scr"
	condition:
		true
}

//include "e:/rxwg/analyze/address.yar"

//基础类分析
include "e:/rxwg/analyze/CheckBasicStructs.yar"
include "e:/rxwg/analyze/CRxEdit.yar"
include "e:/rxwg/analyze/CRxLabel.yar"
include "e:/rxwg/analyze/CRxLabelEx.yar"
include "e:/rxwg/analyze/CRxCombo.yar"
include "e:/rxwg/analyze/CRxListBox.yar"
include "e:/rxwg/analyze/CRxButton.yar"
include "e:/rxwg/analyze/CRxWnd.yar"
include "E:/rxwg/analyze/CRxStuff.yar"
include "e:/rxwg/analyze/CRxList.yar"

//include "e:/rxwg/analyze/CRxMgrLogin.yar"
//include "e:/rxwg/analyze/CRxMgrRole.yar"
//include "e:/rxwg/analyze/CRxSelf.yar"
//include "E:/rxwg/analyze/CRxSocket.yar"
//include "E:/rxwg/analyze/CRxNpc.yar"
//include "E:/rxwg/analyze/CRxPlayer.yar"
//include "E:/rxwg/analyze/CRxGroundStuff.yar"
//include "E:/rxwg/analyze/CRxPicker.yar"
//include "e:/rxwg/analyze/CRxMgrMakerFrame.yar"
//include "e:/rxwg/analyze/CRxMgrMaker.yar"
//include "e:/rxwg/analyze/CRxMgrMyShop.yar"
//include "e:/rxwg/analyze/CRxMgrShop.yar"



//include "e:/rxwg/analyze/CRxMgrNpc.yar"
//include "E:/rxwg/analyze/CRxMgrPk.yar"
//include "E:/rxwg/analyze/CRxMgrZd.yar"
//include "E:/rxwg/analyze/CRxMgrThl.yar"
//include "E:/rxwg/analyze/CRxMgrConfig.yar"
//include "E:/rxwg/analyze/CRxMgrState.yar"
//include "E:/rxwg/analyze/CRxMgrCharm.yar"





//include "e:/rxwg/analyze/CRxApp.yar"

rule main_finish
{
	meta:
		script = "log \"Running script finished!\""
		script = "yaraEx.ll 2"
	condition:
		true
}

