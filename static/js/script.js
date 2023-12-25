function generateQRCode() {
  var qrURL = document.getElementById("url").value;
  document.querySelector('footer').style.height = '50px';
  /**
  var qrContainer = document.getElementById("qrcode");

  var options = {
    text: qrURL,
    width: 256,
    height: 256,
    logo: "./images/teamname.png",
    logoWidth: 128,
    logoHeight: 128,
    logoBackgroundTransparent: true,
    correctLevel: QRCode.CorrectLevel.H,
  };

  new QRCode(qrContainer, options);

  document.getElementById("url").value = "";
  
  
  **/

  var data = { url: qrURL };

  $.ajax({
    url: "/API/qr-generator",
    type: "POST",
    contentType: "application/json",
    data: JSON.stringify(data),
    success: function (response) {
      var qrContainer = document.getElementById("qrcode");
      qrContainer.innerHTML = "";

      if (response.status === "success") {
        const base64_image = response.base64_image;
        console.log(base64_image);
        qrContainer.innerHTML =
          '<img src="data:image/png;base64,' +
          base64_image +
          '" style="width:256px;height:256px;"/>';
          
          var buttons = document.querySelectorAll('.button2');
          buttons.forEach(function (button) {
            button.style.display = 'inline-block';
          });

      } else {
        qrContainer.innerHTML = "Error: " + response.message;
      }
    },
    error: function (xhr, status, error) {
      var qrContainer = document.getElementById("qrcode");

      qrContainer.innerHTML = "";
      qrContainer.innerHTML = "Request Failed: " + error;
    },
  });

  document.getElementById("url").value = "";
}


function enterkey() {
	if (window.event.keyCode == 13) {
        generateQRCode();
    }
}

function copyQRCodeImage() {
  var qrContainer = document.getElementById("qrcode");
  var img = qrContainer.querySelector('img');

  // Check if Clipboard API is supported
  if (navigator.clipboard) {
    // Fetch the image as a Blob
    fetch(img.src)
      .then(response => response.blob())
      .then(blob => {
        // Use Clipboard API to write the Blob to the clipboard
        navigator.clipboard.write([
          new ClipboardItem({
            'image/png': blob
          })
        ]).then(function () {
          alert("QR 코드 이미지가 복사되었습니다.");
        }).catch(function (err) {
          console.error('Unable to copy QR code image', err);
        });
      })
      .catch(err => {
        console.error('Error fetching QR code image', err);
      });
  } else {
    // Clipboard API not supported, provide fallback or message
    console.error('Clipboard API not supported');
  }
}


function saveQRCode() {
  var qrContainer = document.getElementById("qrcode");
  var img = qrContainer.querySelector('img');

  var link = document.createElement('a');
  link.href = img.src;
  link.download = 'qrcode.png';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  alert("QR 코드가 저장되었습니다.");
}
function updateVisitorCount() {
  const today = new Date().toDateString();
  let lastVisitDate = localStorage.getItem("lastVisitDate");
  let count = localStorage.getItem("visitorCount");

  if (lastVisitDate !== today) {
    count = 0;
    localStorage.setItem("lastVisitDate", today);
  } else {
    count = count ? parseInt(count) : 0;
  }

  localStorage.setItem("visitorCount", count + 1);
  document.getElementById(
    "visitorCount"
  ).innerText = `Today's Visitors: ${count}`;
}

window.onload = function () {
  updateVisitorCount();
};



