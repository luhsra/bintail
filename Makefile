DEPDIR=.d
$(shell mkdir -p $(DEPDIR) >/dev/null)
POSTCOMPILE = mv -f $(DEPDIR)/$*.Td $(DEPDIR)/$*.d

CXX=clang++
RM=rm -f
CXXFLAGS=-Wall -Wextra -g -std=c++2a
CXXFLAGS+=-MT $@ -MMD -MP -MF $(DEPDIR)/$*.Td
LDFLAGS=-g
LDLIBS=-lelf

SRCS=bintail.cpp main.cpp mvpp.cpp mvscn.cpp mvvar.cpp
OBJS=$(subst .cpp,.o,$(SRCS))

all: bintail
	$(MAKE) -C samples

bintail: $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

depend: .depend

.depend: $(SRCS)
	$(RM) ./.depend
	$(CXX) $(CPPFLAGS) -MM $^>> ./.depend

clean:
	$(RM) $(OBJS)
	$(MAKE) -C samples clean

test:
	./test.sh || echo "FAILED"

%.o : %.cc
%.o : %.cc $(DEPDIR)/%.d $(EXTRA_DEPS)
	$(CXX) -o $@ -c $< $(CXXFLAGS)
	@$(POSTCOMPILE)


$(DEPDIR)/%.d: ;
.PRECIOUS: $(DEPDIR)/%.d

-include $(patsubst %,$(DEPDIR)/%.d,$(basename $(SRCS)))
