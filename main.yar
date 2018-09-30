//�ļ����뱣��Ϊutf8��ʽ��������x64dbg��־������Ļ��������

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

//������
include "e:/rxwg/analyze/CheckBasicStructs.yar"

//�ؼ���
include "e:/rxwg/analyze/CRxEdit.yar"
include "e:/rxwg/analyze/CRxLabel.yar"
include "e:/rxwg/analyze/CRxLabelEx.yar"
include "e:/rxwg/analyze/CRxCombo.yar"
include "e:/rxwg/analyze/CRxListBox.yar"
include "e:/rxwg/analyze/CRxButton.yar"
include "e:/rxwg/analyze/CRxWnd.yar"
include "e:/rxwg/analyze/CRxImage.yar"

//��Ʒ��
include "E:/rxwg/analyze/CRxStuff.yar"
include "e:/rxwg/analyze/CRxList.yar"
include "e:/rxwg/analyze/CRxSelf.yar"

//��ɫ��
include "e:/rxwg/analyze/CRxPet.yar"
include "E:/rxwg/analyze/CRxNpc.yar"
include "E:/rxwg/analyze/CRxPlayer.yar"
include "E:/rxwg/analyze/CRxGroundStuff.yar"

//��¼ѡ��������
include "e:/rxwg/analyze/CRxMgrLogin.yar"

//��¼ѡ��ɫ������
include "e:/rxwg/analyze/CRxMgrRole.yar"

//ϵͳ���߹�����
include "e:/rxwg/analyze/CRxMgrTool.yar"

//���������
include "e:/rxwg/analyze/CRxMgrMakerFrame.yar"
include "e:/rxwg/analyze/CRxMgrMaker.yar"

//PK������
include "E:/rxwg/analyze/CRxMgrFynode.yar"
include "E:/rxwg/analyze/CRxMgrFymap.yar"
include "E:/rxwg/analyze/CRxMgrFypk.yar"
include "E:/rxwg/analyze/CRxMgrPk.yar"

//���������
include "e:/rxwg/analyze/CRxMgrMyShop.yar"

//NPC�̵������
include "e:/rxwg/analyze/CRxMgrShop.yar"

//NPC�ϳ�����ʯ������
include "e:/rxwg/analyze/CRxMgrSxstone.yar"

//�ֿ������
include "e:/rxwg/analyze/CRxWndDepot.yar"
include "e:/rxwg/analyze/CRxMgrDepot.yar"

//�ϳɹ�����
include "e:/rxwg/analyze/CRxMgrUnite.yar"

//ǿ��������
include "e:/rxwg/analyze/CRxMgrStrong.yar"

//���������
include "e:/rxwg/analyze/CRxMgrRaise.yar"

//���ߴ��͹�����
include "e:/rxwg/analyze/CRxMgrPortal.yar"

//NPC������
include "e:/rxwg/analyze/CRxMgrNpc.yar"

//include "E:/rxwg/analyze/CRxMgrZd.yar"
//include "E:/rxwg/analyze/CRxMgrThl.yar"
//include "E:/rxwg/analyze/CRxMgrConfig.yar"
//include "E:/rxwg/analyze/CRxMgrState.yar"
//include "E:/rxwg/analyze/CRxMgrCharm.yar"

//����
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

