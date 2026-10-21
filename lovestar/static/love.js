(function(){
  "use strict";
  const input=document.getElementById('photoFile'), preview=document.getElementById('photoPreview');
  const initialSource=preview?.getAttribute('src');
  let previewURL;
  if(input&&preview)input.addEventListener('change',()=>{
    if(previewURL)URL.revokeObjectURL(previewURL);
    input.setCustomValidity('');
    const file=input.files[0];
    if(!file){if(initialSource){preview.src=initialSource;preview.hidden=false;}else{preview.removeAttribute('src');preview.hidden=true;}return;}
    if(file.size>8*1024*1024){input.setCustomValidity('照片请控制在 8 MB 以内。');input.reportValidity();return;}
    input.setCustomValidity('');previewURL=URL.createObjectURL(file);preview.src=previewURL;preview.hidden=false;
  });
  document.addEventListener('keydown',event=>{if(event.key==='Escape')document.querySelectorAll('details[open]').forEach(node=>{node.open=false;node.querySelector('summary')?.focus();});});
  document.addEventListener('click',event=>{document.querySelectorAll('.account-menu[open]').forEach(node=>{if(!node.contains(event.target))node.open=false;});});
})();
