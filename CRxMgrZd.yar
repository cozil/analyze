rule CRxMgrZd_start
{
	meta:
		script = "log \"struct CRxMgrZd {\""
	condition:
		true
}

//390 CRxWnd * dlg_goback;
//394 CRxButton * bn_goback;
rule CRxMgrZd_dlg_goback
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "log \"/*{p:$result}*/    CRxWnd * dlg_goback;\""
		
		script = "$result = [@pattern + 0x48]"
		script = "log \"/*{p:$result}*/    CRxButton * bn_goback;\""
	strings:
	
		//ָ��CRxMgrZd�Ĺ��캯��
		//�鿴��ZdMgr��ֵ�����ã������ҵ����캯��
		//����dlg_goback����ʱ�����˴���ͼƬ��
		//..\\datas\\interface\\DATA\\etc\\forcewar_Move_Village_button_none.bmp
		
		$pattern = { 89 86 [4] E8 [4] D9 EE 8B 8E [4] D9 95 [4] 8B 85 [4] D9 9D [4] 8B 95 [4] 53 53 68 C8 00 00 00 68 [4] 68 [4] 53 52 50 51 56 E8 [4] 89 86 [4] 8B 15 [4]D1 EA 81 EA 90 01 00 00}
	condition:
		#pattern == 1
}


rule CRxMgrZd_end
{
	meta:
		script = "log }"
		script = "log"
		script = "log"
	condition:
		true
}