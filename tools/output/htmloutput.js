function showSyscallBody(sysno) {
    var e = document.getElementById("sys" + sysno);
    e = e.getElementsByClassName("sysbody")[0];

    var style = e.style.display;
    if (style == "") {
        style = e.currentStyle ? e.currentStyle.display :
            getComputedStyle(e, null).display;
    }

    // Switch style
    style = (style == "none") ? "block" : "none";
    e.style.display = style;
}

function gotoSyscall(sysno) {
    showSyscallBody(sysno);

    var e = document.getElementById("sys" + sysno);
    e.scrollIntoView();
}
