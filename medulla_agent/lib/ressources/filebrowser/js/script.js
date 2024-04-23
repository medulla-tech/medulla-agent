jQuery(document).ready( function () {
    jQuery(jstablenames).DataTable();
    jQuery( "#tabs" ).tabs();
    jQuery( ".resizable" ).resizable();

    redirect = function(url){
      console.log(document.location)
      console.log(url)

      document.location.href= 'test' + url;
    }


    show_dialog = function(tablename, element, selector){
        list = jQuery('#table-'+tablename+' .sorting_1 a')


        link_list = []
        list.each(function(id, link){
            link_list.push(link)
        })

        total = link_list.length
        index = link_list.indexOf(selector)

        previous = index - 1;
        next = index + 1;

        if(previous < 0)
            previous = 0;
        if(next > total - 1){
            next = total - 1;
        }

        dialog = jQuery('#dialog');
        dialog_content = jQuery('#dialog object')
        dialog_content.attr('data', tablename+"/"+element)
        dialog_content.html("<a href='"+tablename+"/"+element+"'></a>");
        dialog_image = dialog_content.find('a')

        dialog_content.css('max', '400px');
        dialog_content.css('max-width', '800px');
        dialog_content.css('max-height', '600px');


        jQuery('#dialog').dialog({
            title: element,
            width: 'auto',
            height: "auto",
            buttons: {
                "Precedent": function() {
                    jQuery( this ).dialog( "close" );
                    jQuery(list[previous]).trigger('click')
                },
                'Next': function() {
                  jQuery( this ).dialog( "close" );
                  jQuery(list[next]).trigger('click')
                }
            },
            _allowInteraction: function(event){
                console.log(event)
            }
        })
    }
});
