NAME=decyber
CREDITS=options.html
IMAGES= decyber-128.png decyber-16.png decyber-48.png
CONTENT=decyber.js decyberlib.js manifest.json $(CREDITS) $(IMAGES)

zip: $(CREDITS)
	test -d $(NAME) || mkdir $(NAME)
	-rm $(NAME)/*
	cp $(CONTENT) $(NAME)/
	zip -r $(NAME).zip $(NAME)

$(CREDITS): options.txt
	fastblog < options.txt > $(CREDITS)

clean:
	-rm *~
	-rm -r $(NAME).zip $(NAME)
