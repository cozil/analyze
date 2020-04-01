//文件必须保存为utf8格式，否则在x64dbg日志输出中文会出现乱码

rule main_start
{
	meta:
		script = "log \"Start running script!\""
		script = "yaraEx.ll 0"
		script = "Type.removeAll"
		script = "Array.removeAll"
		script = "labelclear"
	condition:
		true
}

include "globalfunc.yar"
include "address.yar"

//基础类定义与检查
include "CheckBasicStructs.yar"

//控件类
include "CRxEdit.yar"
include "CRxLabel.yar"
include "CRxLabelEx.yar"
include "CRxCombo.yar"
include "CRxListBox.yar"
include "CRxButton.yar"
include "CRxWnd.yar"
include "CRxImage.yar"

//物品类
include "CRxStuff.yar"
include "CRxMgrList.yar"
include "CRxSelf.yar"

//角色类
include "CRxPet.yar"
include "CRxNpc.yar"
include "CRxPlayer.yar"
include "CRxGroundStuff.yar"

//登录选服管理类
include "CRxMgrLogin.yar"

//登录选角色管理类
include "CRxMgrRole.yar"

//真斗烈战管理
include "CRxMgrZd.yar"

//谭花灵必杀管理
include "CRxMgrThl.yar"

//鼠标拾取管理
include "CRxPicker.yar"

//通讯管理
include "CRxSocket.yar"


//系统工具管理类
include "CRxMgrTool.yar"

//制造管理类
include "CRxMgrMakerFrame.yar"
include "CRxMgrMaker.yar"

//PK管理类
include "CRxMgrFynode.yar"
include "CRxMgrFymap.yar"
include "CRxMgrFypk.yar"
include "CRxMgrPk.yar"

//开店管理类
include "CRxMgrMyShop.yar"

//NPC商店管理类
include "CRxMgrShop.yar"

//NPC合成属性石管理类
include "CRxMgrSxstone.yar"

//仓库管理类
include "CRxMgrDepot.yar"

//合成管理类
include "CRxMgrUnite.yar"

//强化管理类
include "CRxMgrStrong.yar"

//单线传送管理类
include "CRxMgrPortal.yar"

//提真管理类
include "CRxMgrRaise.yar"

//NPC管理类
include "CRxMgrNpc.yar"

//角色属性管理类
include "CRxMgrState.yar"

//角色装备/背包管理类
include "CRxMgrExtBag.yar"
include "CRxMgrEquip.yar"

//游戏设置管理类
include "CRxMgrConfig.yar"

//场景地图管理类
include "CRxMgrMap.yar"

//强制退出游戏管理类
include "CRxMgrExit.yar"

//任务管理类
include "CRxMgrTask.yar"

//情侣管理
include "CRxMgrFlower.yar"
include "CRxMgrSweetState.yar"
include "CRxMgrSweet.yar"

//制药管理
include "CRxMgrDrug.yar"

//死亡保护管理
include "CRxMgrDead.yar"

//交易管理
include "CRxMgrTradeTip.yar"
include "CRxMgrTrade.yar"

//队伍管理
include "CRxMgrMember.yar"
include "CRxMgrTeam.yar"

//土灵符管理
include "CRxMgrTlf.yar"

//热血至尊符管理
include "CRxMgrCharm.yar"

//宠物管理
include "CRxMgrPet.yar"

//师徒管理
include "CRxMgrMaster.yar"


//程序管理器
include "CRxApp.yar"

rule main_finish
{
	meta:
		script = "log \"Running script finished!\""
		script = "yaraEx.ll 2"
	condition:
		true
}

