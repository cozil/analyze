rule CRxMgrTask_start
{
	meta:
		script = "Type.as CRxMgrTask"
		script = "Type.comment CRxMgrTask,\"任务管理\""
		script = "Type.ad CRxMgrTask,\"inline void click_tasklist_close() {{ click(0x3eb); }}\""
		script = "Type.ad CRxMgrTask,\"inline void click_taskdetail_reject() {{ click(0x3e9); }}\""
		script = "Type.ad CRxMgrTask,\"inline void click_taskdetail_close() {{ click(0x3e9); }}\""
		script = "Type.ad CRxMgrTask,\"inline void click_taskdetail_accept() {{ click(0x3ed); }}\""
	condition:
		true
}

//250 CRxWnd * dlg_mytasks;
rule CRxMgrTask_dlg_mytasks
{
	meta:
		script = "$result = [@pattern + 0x19]"
		script = "Type.am CRxMgrTask,CRxWnd*,dlg_mytasks,0,$result"
		script = "Type.mcomment CRxMgrTask,dlg_mytasks,\"玩家已接受的任务列表窗口\""
	strings:
		$pattern = { 68 2A 23 00 00 68 [4] 68 [6] 89 [5] 8B [8] E8 }
	condition:
		#pattern == 1
}

//25c CRxListBox * mytasks_listbox;
rule CRxMgrTask_mytasks_listbox
{
	meta:
		script = "$result = [@pattern + 0x38]"
		script = "Type.am CRxMgrTask,CRxListBox*,mytasks_listbox,0,$result"
	strings:
		$pattern = { 6A 01 [18] 6A 16 [18] 6A 02 [12] 89 }
	condition:
		#pattern == 1
}

//3d8 CRxWnd * dlg_alltasks;
//3e0 CRxListBox * alltasks_listbox;
rule CRxMgrTask_dlg_alltasks
{
	meta:
		script = "$result = [@pattern + 0x25]"
		script = "Type.am CRxMgrTask,CRxWnd*,dlg_alltasks,0,$result"
		script = "Type.mcomment CRxMgrTask,dlg_alltasks,\"所有任务列表窗口\""
		script = "$result = [@pattern + 0x2f]"
		script = "Type.am CRxMgrTask,CRxListBox*,alltasks_listbox,0,$result"
	strings:
		$pattern = { C7 [5] 25 00 00 00 C7 [5] 1E 00 00 00 C7 [5] A0 00 00 00 E8 [4] 8B [9] 89 [5] E8 [4] D9 05 }
	condition:
		#pattern == 1
}

//3fc RX_GAME_TASK currentTask;
rule CRxMgrTask_currentTask
{
	meta:
		script = "$result = [@pattern + 0xe]"
		script = "Type.am CRxMgrTask,RX_GAME_TASK,currentTask,0,$result"
		script = "Type.mcomment CRxMgrTask,currentTask,\"成功找到此成员偏移时，表示结构大小未变化\""
	strings:
		$pattern = { 69 ?? D4 00 00 00 03 [5] 8D [6] E8 [4] 68 4E 01 00 00 }
	condition:
		#pattern == 1
}

//4d0 int npc_index;
rule CRxMgrTask_npc_index
{
	meta:
		script = "$result = [@pattern + 0x2]"
		script = "Type.am CRxMgrTask,int,npc_index,0,$result"
		script = "Type.mcomment CRxMgrTask,npc_index,\"当前打开的任务窗口所属NPC序号，只有打开任务窗口时才会设置此值\""
	strings:
		$pattern = { 8B [5] 8B [6] 6A 04 6A 00 [2] 89 [5] E8 [4] 6A 00 6A 02 6A 01 }
	condition:
		#pattern == 1
}

//5d8 CRxWn * dlg_taskdetail;
rule CRxMgrTask_dlg_taskdetail
{
	meta:
		script = "$result = [@pattern + 0xa]"
		script = "Type.am CRxMgrTask,CRxWnd*,dlg_taskdetail,0,$result"
		script = "Type.mcomment CRxMgrTask,dlg_alltasks,\"任务接受/拒绝窗口\nflag标志定义 0:显示任务列表 1:显示任务接受拒绝确认 2:显示接受拒绝结果\""
	strings:
		$pattern = { C6 [2] 0F [4] 8B [5] 68 FF 00 00 00 6A FF [3] 68 8C 00 00 00 68 DE 00 00 00 [2] E8 }
	condition:
		#pattern == 1
}

//278 CRxButton * taskdetail_bn_reject;
//rule CRxMgrTask_taskdetail_bn_reject
//{
//	meta:
//		script = "$result = [@pattern + 0x1f]"
//		script = "Type.am CRxMgrTask,CRxButton*,taskdetail_bn_reject,0,$result"
//		script = "Type.mcomment CRxMgrTask,taskdetail_bn_reject,\"“拒绝”按钮\""
//	strings:
//		$pattern = { 68 E9 03 00 00 68 [8] E8 [4] 83 C4 38 68 [6] 89 [5] E8 [10] 6A 01 }
//	condition:
//		#pattern == 1
//}

//280 CRxButton * taskdetail_bn_close;
//rule CRxMgrTask_taskdetail_bn_close
//{
//	meta:
//		script = "$result = [@pattern + 0x25]"
//		script = "Type.am CRxMgrTask,CRxButton*,taskdetail_bn_close,0,$result"
//		script = "Type.mcomment CRxMgrTask,taskdetail_bn_reject,\"“确认”按钮\""
//	strings:
//		$pattern = { 68 E9 03 00 00 68 [8] 89 [5] E8 [4] 83 C4 20 68 [6] 89 [5] E8 [4] 8B [5] 6A 01 }
//	condition:
//		#pattern == 1
//}


//284 CRxButton * taskdetail_bn_accept;
//rule CRxMgrTask_taskdetail_bn_accept
//{
//	meta:
//		script = "$result = [@pattern + 0x1f]"
//		script = "Type.am CRxMgrTask,CRxButton*,taskdetail_bn_accept,0,$result"
//		script = "Type.mcomment CRxMgrTask,taskdetail_bn_accept,\"“接受”按钮\""
//	strings:
//		$pattern = { 68 ED 03 00 00 68 [8] E8 [4] 83 C4 20 68 [6] 89 [5] E8 [4] 8B [5] 6A 01 }
//	condition:
//		#pattern == 1
//}

//624 CRxLabel * taskdetail_lb_accept;
rule CRxMgrTask_taskdetail_lb_accept
{
	meta:
		script = "$result = [@pattern + 0x17]"
		script = "Type.am CRxMgrTask,CRxLabel*,taskdetail_lb_accept,0,$result"
		script = "Type.mcomment CRxMgrTask,taskdetail_lb_accept,\"“接受”按钮的标签，visible=1表示按钮可视\""
	strings:
		$pattern = { 6A 05 68 F0 00 00 00 6A 1A [2] E8 [9] 89 [5] 8B [5] 68 1B 11 00 00 C6 [2] 09 }
	condition:
		#pattern == 1
}

//628 CRxLabel * taskdetail_lb_reject;
//rule CRxMgrTask_dlg_lb_reject
//{
//	meta:
//		script = "$result = [@pattern + 0x17]"
//		script = "Type.am CRxMgrTask,CRxLabel*,taskdetail_lb_reject,0,$result"
//		script = "Type.mcomment CRxMgrTask,taskdetail_lb_reject,\"“拒绝”按钮的标签，visible=1表示按钮可视\""
//	strings:
//		$pattern = { 6A 05 68 1D 01 00 00 6A 1A [2] E8 [9] 89 [5] 8B [5] 68 1C 11 00 00 C6 [2] 09 }
//	condition:
//		#pattern == 1
//}

//630 CRxLabel * taskdetail_lb_close;
//rule CRxMgrTask_taskdetail_lb_close
//{
//	meta:
//		script = "$result = [@pattern + 0x17]"
//		script = "Type.am CRxMgrTask,CRxLabel*,taskdetail_lb_close,0,$result"
//		script = "Type.mcomment CRxMgrTask,taskdetail_lb_close,\"“确认”按钮的标签，visible=1表示按钮可视\""
//	strings:
//		$pattern = { 6A 05 68 1D 01 00 00 6A 1A [2] E8 [9] 89 [5] 8B [5] 68 1E 11 00 00 }
//	condition:
//		#pattern == 1
//}




rule CRxMgrTask_end
{
	meta:
		script = "Type.print CRxMgrTask,$_OUT_OFFLEN,$_OUT_TYPELEN,$_OUT_NAMELEN"
	condition:
		true
}