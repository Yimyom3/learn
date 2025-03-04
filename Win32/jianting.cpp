//LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
//{
//	if (nCode == HC_ACTION && wParam == WM_KEYUP) {
//		PKBDLLHOOKSTRUCT ks = (PKBDLLHOOKSTRUCT)lParam;
//		if (ks->flags == 128 || ks->flags == 129)
//		{
//			DWORD vkCode = ks->vkCode;
//			if (vkCode >= 0x30 && vkCode < 0x3A) {
//				cout << "input: " << (CHAR)vkCode << endl;
//			}else if(vkCode >= 0x60 && vkCode < 0x6A)
//			{
//				cout << "input: " << (CHAR)(vkCode - 0x30) << endl;
//			}
//			else if(vkCode >= 0x41 && vkCode < 0x5B)
//			{
//				cout << "input: " << (CHAR)(vkCode) << endl;
//			}
//			else
//			{
//				cout << "input virtual key code: 0x" << hex << vkCode << endl;
//			}
//		}
//	}
//	return CallNextHookEx(NULL, nCode, wParam, lParam);
//}

//int _tmain(int argc, _TCHAR* argv[])
//{
//	HHOOK keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, NULL);
//	if (keyboardHook == 0) {
//		return -1;
//	}
//	MSG msg;
//	while (TRUE)
//	{
//		if (PeekMessageA(&msg, NULL, WM_KEYFIRST, WM_KEYLAST, PM_REMOVE)) {
//			TranslateMessage(&msg);
//			DispatchMessageW(&msg);
//		}
//		else {
//			Sleep(0);
//		}
//	}
//	UnhookWindowsHookEx(keyboardHook);
//	return 0;
//}
//
//LRESULT CALLBACK HookCallback(int code, WPARAM wParam, LPARAM lParam) {
//	if (*(DWORD*)(lParam + 8) == 0x1EB) { //判断消息是不是0x1EB
//		if (UnhookWindowsHook(WH_CALLWNDPROC, HookCallback)) {
//			SetWindowLongA(*(HWND*)(lParam + 12), GWLP_WNDPROC, (LONG)HookCallbackTwo); //消息的窗口的句柄
//		}
//	}
//	return CallNextHookEx(0, code, wParam, lParam);
//}
