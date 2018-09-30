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

include "e:/rxwg/analyze/globalfunc.yar"
include "e:/rxwg/analyze/address.yar"

//基础类
include "e:/rxwg/analyze/CheckBasicStructs.yar"

//控件类
include "e:/rxwg/analyze/CRxEdit.yar"
include "e:/rxwg/analyze/CRxLabel.yar"
include "e:/rxwg/analyze/CRxLabelEx.yar"
include "e:/rxwg/analyze/CRxCombo.yar"
include "e:/rxwg/analyze/CRxListBox.yar"
include "e:/rxwg/analyze/CRxButton.yar"
include "e:/rxwg/analyze/CRxWnd.yar"
include "e:/rxwg/analyze/CRxImage.yar"

//物品类
include "E:/rxwg/analyze/CRxStuff.yar"
include "e:/rxwg/analyze/CRxList.yar"
include "e:/rxwg/analyze/CRxSelf.yar"

//角色类
include "e:/rxwg/analyze/CRxPet.yar"
include "E:/rxwg/analyze/CRxNpc.yar"
include "E:/rxwg/analyze/CRxPlayer.yar"
include "E:/rxwg/analyze/CRxGroundStuff.yar"

//登录选服管理类
include "e:/rxwg/analyze/CRxMgrLogin.yar"

//登录选角色管理类
include "e:/rxwg/analyze/CRxMgrRole.yar"

//系统工具管理类
include "e:/rxwg/analyze/CRxMgrTool.yar"

//制造管理类
include "e:/rxwg/analyze/CRxMgrMakerFrame.yar"
include "e:/rxwg/analyze/CRxMgrMaker.yar"

//PK管理类
include "E:/rxwg/analyze/CRxMgrFynode.yar"
include "E:/rxwg/analyze/CRxMgrFymap.yar"
include "E:/rxwg/analyze/CRxMgrFypk.yar"
include "E:/rxwg/analyze/CRxMgrPk.yar"

//开店管理类
include "e:/rxwg/analyze/CRxMgrMyShop.yar"

//NPC商店管理类
include "e:/rxwg/analyze/CRxMgrShop.yar"

//NPC合成属性石管理类
include "e:/rxwg/analyze/CRxMgrSxstone.yar"

//仓库管理类
include "e:/rxwg/analyze/CRxWndDepot.yar"
include "e:/rxwg/analyze/CRxMgrDepot.yar"

//合成管理类
include "e:/rxwg/analyze/CRxMgrUnite.yar"

//强化管理类
include "e:/rxwg/analyze/CRxMgrStrong.yar"

//提真管理类
include "e:/rxwg/analyze/CRxMgrRaise.yar"

//单线传送管理类
include "e:/rxwg/analyze/CRxMgrPortal.yar"

//NPC管理类
include "e:/rxwg/analyze/CRxMgrNpc.yar"

//include "E:/rxwg/analyze/CRxMgrZd.yar"
//include "E:/rxwg/analyze/CRxMgrThl.yar"
//include "E:/rxwg/analyze/CRxMgrConfig.yar"
//include "E:/rxwg/analyze/CRxMgrState.yar"
//include "E:/rxwg/analyze/CRxMgrCharm.yar"

//其它
include "E:/rxwg/analyze/CRxPicker.yar"
include "E:/rxwg/analyze/CRxSocket.yar"




//include "e:/rxwg/analyze/CRxApp.yar"

rule main_finish
{
	meta:
		script = "log \"Running script finished!\""
		script = "yaraEx.ll 2"
	condition:
		true
}

