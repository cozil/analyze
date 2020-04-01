//�ļ����뱣��Ϊutf8��ʽ��������x64dbg��־������Ļ��������

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

//�����ඨ������
include "CheckBasicStructs.yar"

//�ؼ���
include "CRxEdit.yar"
include "CRxLabel.yar"
include "CRxLabelEx.yar"
include "CRxCombo.yar"
include "CRxListBox.yar"
include "CRxButton.yar"
include "CRxWnd.yar"
include "CRxImage.yar"

//��Ʒ��
include "CRxStuff.yar"
include "CRxMgrList.yar"
include "CRxSelf.yar"

//��ɫ��
include "CRxPet.yar"
include "CRxNpc.yar"
include "CRxPlayer.yar"
include "CRxGroundStuff.yar"

//��¼ѡ��������
include "CRxMgrLogin.yar"

//��¼ѡ��ɫ������
include "CRxMgrRole.yar"

//�涷��ս����
include "CRxMgrZd.yar"

//̷�����ɱ����
include "CRxMgrThl.yar"

//���ʰȡ����
include "CRxPicker.yar"

//ͨѶ����
include "CRxSocket.yar"


//ϵͳ���߹�����
include "CRxMgrTool.yar"

//���������
include "CRxMgrMakerFrame.yar"
include "CRxMgrMaker.yar"

//PK������
include "CRxMgrFynode.yar"
include "CRxMgrFymap.yar"
include "CRxMgrFypk.yar"
include "CRxMgrPk.yar"

//���������
include "CRxMgrMyShop.yar"

//NPC�̵������
include "CRxMgrShop.yar"

//NPC�ϳ�����ʯ������
include "CRxMgrSxstone.yar"

//�ֿ������
include "CRxMgrDepot.yar"

//�ϳɹ�����
include "CRxMgrUnite.yar"

//ǿ��������
include "CRxMgrStrong.yar"

//���ߴ��͹�����
include "CRxMgrPortal.yar"

//���������
include "CRxMgrRaise.yar"

//NPC������
include "CRxMgrNpc.yar"

//��ɫ���Թ�����
include "CRxMgrState.yar"

//��ɫװ��/����������
include "CRxMgrExtBag.yar"
include "CRxMgrEquip.yar"

//��Ϸ���ù�����
include "CRxMgrConfig.yar"

//������ͼ������
include "CRxMgrMap.yar"

//ǿ���˳���Ϸ������
include "CRxMgrExit.yar"

//���������
include "CRxMgrTask.yar"

//���¹���
include "CRxMgrFlower.yar"
include "CRxMgrSweetState.yar"
include "CRxMgrSweet.yar"

//��ҩ����
include "CRxMgrDrug.yar"

//������������
include "CRxMgrDead.yar"

//���׹���
include "CRxMgrTradeTip.yar"
include "CRxMgrTrade.yar"

//�������
include "CRxMgrMember.yar"
include "CRxMgrTeam.yar"

//���������
include "CRxMgrTlf.yar"

//��Ѫ���������
include "CRxMgrCharm.yar"

//�������
include "CRxMgrPet.yar"

//ʦͽ����
include "CRxMgrMaster.yar"


//���������
include "CRxApp.yar"

rule main_finish
{
	meta:
		script = "log \"Running script finished!\""
		script = "yaraEx.ll 2"
	condition:
		true
}

