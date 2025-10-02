package com.venusim.auth.domain.member;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
public class MemberService {

    private final MemberSsoRandomRepository repository;
    private final MemberSsoRandomQueryRepository queryRepository;

    public MemberService(MemberSsoRandomRepository repository, MemberSsoRandomQueryRepository queryRepository) {
        this.repository = repository;
        this.queryRepository = queryRepository;
    }

    /** id+code 일치 && date_permission이 현재 기준 10분 이내인지 */
    @Transactional(readOnly = true)
    public boolean isValid(String idMember, String code) {
        LocalDateTime threshold = LocalDateTime.now().minusMinutes(10);
        return queryRepository.existsValid(idMember, code, threshold);
//        return repository.existsByIdMemberAndCoedRandomAndDatePermissionAfter(idMember, code, threshold);
    }
}