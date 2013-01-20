#ifndef XTAAK_XTAAK_H_
#define XTAAK_XTAAK_H_

#include <stdlib.h>

namespace Xtaak {

#ifndef MIE_INTEGER_TYPE_DEFINED
#define MIE_INTEGER_TYPE_DEFINED
typedef unsigned char uint8;
#endif

class CodeArray {
protected:
	size_t maxSize_;
	uint8 *top_;
	size_t size_;

public:
	const uint8 *getCurr() const { return &top_[size_]; }
};

class CodeGenerator : public CodeArray {
};

} // end of namespace

#endif // XTAAK_XTAAK_H_
