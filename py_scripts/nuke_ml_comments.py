
"""
IDA script delete all Missing Link comments from the current IDB
Use after rebasing, before running ML plugin from another TTD trace, etc.
"""
import idaapi
from PyQt5 import QtWidgets


# Make IDA UI process events to see output/log messages now
def _refresh():
    if idaapi.is_idaq():
        QtWidgets.QApplication.instance().processEvents()


def _byte_str(size: int, decimal_places: int = 2):
    """Return pretty byte size string."""
    for unit in ['bytes', 'KB', 'MB', 'GB', 'TB', 'PB']:
        if size < 1024.0 or unit == 'PB':
            break
        size /= 1024.0
    return f'{size:.{decimal_places}f} {unit}'


if idaapi.ask_yn(-1, 'This script will delete all ML "#ML:" comments, continue?') == 1:
    print("Script: Working..")
    idaapi.set_ida_state(idaapi.st_Work)

    # Walk code segments
    removal_count = 0
    for n in range(idaapi.get_segm_qty()):
        seg = idaapi.getnseg(n)
        if seg.type == idaapi.SEG_CODE:
            start_ea = seg.start_ea
            end_ea = seg.end_ea
            print(f'Scanning code segment: "{idaapi.get_segm_name(seg, 0)}" {start_ea:X}-{end_ea:X} {_byte_str(end_ea - start_ea)}..')
            _refresh()

            ea = idaapi.next_head(start_ea, end_ea)
            while ea < end_ea:
                comment = idaapi.get_cmt(ea, False)
                if comment:
                    if comment.startswith('#ML: '):
                        idaapi.set_cmt(ea, '', False)
                        removal_count += 1
                ea = idaapi.next_head(ea, end_ea)

    idaapi.refresh_idaview_anyway()
    print(f'Script: Done, removed {removal_count:,} ML comments.')
else:
    print("Script: Aborted.")
idaapi.set_ida_state(idaapi.st_Ready)
